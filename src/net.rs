//! The network layer for the MPC protocol.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use digest::Digest;
use log::debug;
use rand::RngCore;
use rayon::prelude::*;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

#[derive(Clone, Debug, Default)]
/// Statistics for the network layer.
pub struct Stats {
    /// Number of bytes sent
    pub bytes_sent: usize,
    /// Number of bytes recieved
    pub bytes_recv: usize,
    /// Number of broadcast rounds
    pub n_broadcasts: usize,
    /// Number of rounds with everyone sending to a specific recipient
    pub n_to_recipient: usize,
    /// Number of rounds with everyone receiving from a specific recipient
    pub n_from_sender: usize,
    /// Number of rounds with this party sending to a specific recipient
    pub me_to_recipient: usize,
    /// Number of rounds with this party receiving from a specific sender
    pub me_from_sender: usize,
}

/// The ID of a party in the network, zero-indexed.
pub type PartyId = usize;

#[derive(Debug)]
/// A peer of a party.
struct Peer {
    /// The peer's address.
    addr: SocketAddr,
    /// The TCP stream to the peer.
    stream: Option<TcpStream>,
    // TODO(aozdemir): Make this not an Option.
    // (Requires omitting the entry for this party in Net.)

    // TODO(aozdemir): Add public keys and encryption.
}

#[derive(Default, Debug)]
/// The state of one party in the network for the MPC protocol.
pub struct Net {
    /// This party's ID.
    id: PartyId,
    /// The list of all parties in the network.
    /// There is an entry for each party, including this one.
    /// This party's entry does not have a stream.
    peers: Vec<Peer>,
    stats: Stats,
}

/// Network creation and metadata.
impl Net {
    /// Am I the first party?
    #[inline]
    pub fn am_king(&self) -> bool {
        self.party_id() == 0
    }

    /// How many parties are there?
    pub fn n_parties(&self) -> usize {
        self.peers.len()
    }

    /// What is my party number (0 to n-1)? (Parties are zero-indexed.)
    pub fn party_id(&self) -> PartyId {
        self.id
    }

    /// Get the ip addres of the party.
    pub fn get_party_ip(&self) -> String {
        self.peers[self.party_id()].addr.ip().to_string()
    }

    /// Get the ip address of the host/king.
    pub fn get_host_ip(&self) -> String {
        self.peers[0].addr.ip().to_string()
    }

    /// Helper method to add communication cost from outside protocols.
    pub fn add_communication_cost(&mut self, bytes: usize) {
        dbg!("Added communication cost", bytes);
        self.stats.bytes_sent += bytes;
        dbg!("Stats", self.stats.bytes_sent);
    }

    /// Open connections to all parties.
    fn connect_to_all(&mut self) {
        let timer = start_timer!(|| "Connecting");
        let n = self.peers.len();
        for from_id in 0..n {
            for to_id in (from_id + 1)..n {
                debug!("{} to {}", from_id, to_id);
                if self.id == from_id {
                    let to_addr = self.peers[to_id].addr;
                    debug!("Contacting {}", to_id);
                    let stream = loop {
                        let mut ms_waited = 0;
                        match TcpStream::connect(to_addr) {
                            Ok(s) => break s,
                            Err(e) => match e.kind() {
                                std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset => {
                                    ms_waited += 10;
                                    std::thread::sleep(std::time::Duration::from_millis(10));
                                    if ms_waited % 3_000 == 0 {
                                        debug!("Still waiting");
                                    } else if ms_waited > 30_000 {
                                        panic!("Could not find peer in 30s");
                                    }
                                }
                                _ => {
                                    panic!("Error during FieldChannel::new: {}", e);
                                }
                            },
                        }
                    };
                    stream.set_nodelay(true).unwrap();
                    self.peers[to_id].stream = Some(stream);
                } else if self.id == to_id {
                    debug!("Awaiting {}", from_id);
                    let listener = TcpListener::bind(self.peers[self.id].addr).unwrap();
                    let (stream, _addr) = listener.accept().unwrap();
                    stream.set_nodelay(true).unwrap();
                    self.peers[from_id].stream = Some(stream);
                }
            }
            // Sender for next round waits for note from this sender to prevent race on receipt.
            if from_id + 1 < n {
                if self.id == from_id {
                    self.peers[self.id + 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .write_all(&[0u8])
                        .unwrap();
                } else if self.id == from_id + 1 {
                    self.peers[self.id - 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .read_exact(&mut [0u8])
                        .unwrap();
                }
            }
        }
        // Do a round with the king, to be sure everyone is ready
        let from_all = self.all_send_bytes_to_king(&[self.id as u8]);
        self.all_recv_bytes_from_king(from_all);
        for id in 0..n {
            if id != self.id {
                assert!(self.peers[id].stream.is_some());
            }
        }
        end_timer!(timer);
    }

    /// Initialize the network layer from a file.
    /// The file should contain one HOST:PORT setting per line, corresponding to the addresses of
    /// the parties in increasing order.
    pub fn init_from_file(path: &str, party_id: PartyId) -> Self {
        let f = BufReader::new(File::open(path).expect("host configuration path"));
        let mut peers = Vec::new();
        for line in f.lines() {
            let line = line.unwrap();
            let trimmed = line.trim();
            if trimmed.len() > 0 {
                let addr: SocketAddr = trimmed
                    .parse()
                    .unwrap_or_else(|e| panic!("bad socket address: {}:\n{}", trimmed, e));
                let peer = Peer { addr, stream: None };
                peers.push(peer);
            }
        }
        assert!(party_id < peers.len());
        let mut this = Self {
            id: party_id,
            peers,
            stats: Stats::default(),
        };
        this.connect_to_all();
        this.reset_stats();
        this
    }

    /// Set statistics to zero.
    pub fn reset_stats(&mut self) {
        self.stats = Stats::default();
    }
    /// Get statistics.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

/// Untyped communication methods.
impl Net {
    /// All parties send bytes to each other.
    /// Takes the bytes to send to other parties.
    /// Returns a vector `x` where `x[i]` is the byte-vector received from party `i`.
    // pub fn broadcast_bytes(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
    //     let timer = start_timer!(|| format!("Broadcast {}", bytes.len()));
    //     let m = bytes.len();
    //     let own_id = self.id;

    //     self.stats.bytes_sent += (self.peers.len() - 1) * m;
    //     self.stats.bytes_recv += (self.peers.len() - 1) * m;
    //     self.stats.n_broadcasts += 1;

    //     let r = self
    //         .peers
    //         .par_iter_mut()
    //         .enumerate()
    //         .map(|(id, peer)| {
    //             let mut bytes_in = vec![0u8; m];
    //             if id < own_id {
    //                 let stream = peer.stream.as_mut().unwrap();
    //                 stream.read_exact(&mut bytes_in[..]).unwrap();
    //                 stream.write_all(bytes).unwrap();
    //             } else if id == own_id {
    //                 bytes_in.copy_from_slice(bytes);
    //             } else {
    //                 let stream = peer.stream.as_mut().unwrap();
    //                 stream.write_all(bytes).unwrap();
    //                 stream.read_exact(&mut bytes_in[..]).unwrap();
    //             };
    //             bytes_in
    //         })
    //         .collect();
    //     end_timer!(timer);
    //     r
    // }

    /// Broadcast bytes to all parties sequentially.
    /// Takes the bytes to send.
    /// Returns a vector `x` where `x[i]` is the byte-vector received from party `i`.
    /// This is slower than the parallel version but ensures synchronization if the protocol is not constant round (e.g. iterative).
    pub fn broadcast_bytes_sequential(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let timer = start_timer!(|| format!("Broadcast {}", bytes.len()));
        let m = bytes.len();
        let own_id = self.id;

        // For extra safety, can uncomment the ready signal here to ensure that each call here is synchronized.
        // let ready_signal = [0u8; 1];
        // for id in 0..self.peers.len() {
        //     if id != own_id {
        //         let stream = self.peers[id].stream.as_mut().unwrap();
        //         stream.write_all(&ready_signal).unwrap();
        //         stream.read_exact(&mut [0u8; 1]).unwrap();
        //     }
        // }

        self.stats.bytes_sent += (self.peers.len() - 1) * m;
        self.stats.bytes_recv += (self.peers.len() - 1) * m;
        self.stats.n_broadcasts += 1;

        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

        let r = self
            .peers
            .iter_mut()
            .enumerate()
            .map(|(id, peer)| {
                let mut bytes_in = vec![0u8; m];
                if id < own_id {
                    let stream = peer.stream.as_mut().unwrap();
                    // Read in chunks
                    for chunk in bytes_in.chunks_mut(CHUNK_SIZE) {
                        stream.read_exact(chunk).unwrap();
                    }
                    // Write in chunks
                    for chunk in bytes.chunks(CHUNK_SIZE) {
                        stream.write_all(chunk).unwrap();
                        stream.flush().unwrap(); // Important: flush after each chunk
                    }
                } else if id == own_id {
                    bytes_in.copy_from_slice(bytes);
                } else {
                    let stream = peer.stream.as_mut().unwrap();
                    // Write in chunks
                    for chunk in bytes.chunks(CHUNK_SIZE) {
                        stream.write_all(chunk).unwrap();
                        stream.flush().unwrap(); // Important: flush after each chunk
                    }
                    // Read in chunks
                    for chunk in bytes_in.chunks_mut(CHUNK_SIZE) {
                        stream.read_exact(chunk).unwrap();
                    }
                };
                bytes_in
            })
            .collect();
        end_timer!(timer);
        r
    }

    /// All parties send bytes to the party `recipient`.
    /// Takes the bytes to send.
    /// Returns the bytes received from each party if you're the recipient, or `None` if you're not.
    // pub fn all_send_bytes_to_party(
    //     &mut self,
    //     recipient: PartyId,
    //     bytes: &[u8],
    // ) -> Option<Vec<Vec<u8>>> {
    //     let timer = start_timer!(|| format!("To recipient {}: {} bytes", recipient, bytes.len()));
    //     let m = bytes.len();
    //     let own_id = self.id;

    //     self.stats.n_to_recipient += 1;
    //     let r = if self.id == recipient {
    //         self.stats.bytes_recv += (self.peers.len() - 1) * m;
    //         Some(
    //             self.peers
    //                 .par_iter_mut()
    //                 .enumerate()
    //                 .map(|(id, peer)| {
    //                     let mut bytes_in = vec![0u8; m];
    //                     if id == own_id {
    //                         bytes_in.copy_from_slice(bytes);
    //                     } else {
    //                         let stream = peer.stream.as_mut().unwrap();
    //                         stream.read_exact(&mut bytes_in[..]).unwrap();
    //                     };
    //                     bytes_in
    //                 })
    //                 .collect(),
    //         )
    //     } else {
    //         self.stats.bytes_sent += m;
    //         self.peers[recipient]
    //             .stream
    //             .as_mut()
    //             .unwrap()
    //             .write_all(bytes)
    //             .unwrap();
    //         None
    //     };
    //     end_timer!(timer);
    //     r
    // }

    /// All parties send bytes to the party `recipient` sequentially.
    /// Takes the bytes to send.
    /// Returns the bytes received from each party if you're the recipient, or `None` if you're not.
    /// This is slower than the parallel version but ensures synchronization if the protocol is not constant round (e.g. iterative).
    pub fn all_send_bytes_to_party_sequential(
        &mut self,
        recipient: PartyId,
        bytes: &[u8],
    ) -> Option<Vec<Vec<u8>>> {
        let timer = start_timer!(|| format!("To recipient {}: {} bytes", recipient, bytes.len()));
        let m = bytes.len();
        let own_id = self.id;

        // For extra safety, can uncomment the ready signal here to ensure that each call here is synchronized.
        // let ready_signal = [0u8; 1];
        // for id in 0..self.peers.len() {
        //     if id != own_id {
        //         let stream = self.peers[id].stream.as_mut().unwrap();
        //         stream.write_all(&ready_signal).unwrap();
        //         stream.read_exact(&mut [0u8; 1]).unwrap();
        //     }
        // }
        self.stats.n_to_recipient += 1;
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
        let r = if self.id == recipient {
            Some(
                self.peers
                    .iter_mut()
                    .enumerate()
                    .map(|(id, peer)| {
                        let mut bytes_in = vec![0u8; m];
                        if id == own_id {
                            bytes_in.copy_from_slice(bytes);
                        } else {
                            let stream = peer.stream.as_mut().unwrap();
                            // Read in chunks
                            for chunk in bytes_in.chunks_mut(CHUNK_SIZE) {
                                stream.read_exact(chunk).unwrap();
                            }
                        };
                        bytes_in
                    })
                    .collect(),
            )
        } else {
            self.stats.bytes_sent += m;
            let stream = self.peers[recipient].stream.as_mut().unwrap();
            // Write in chunks
            for chunk in bytes.chunks(CHUNK_SIZE) {
                stream.write_all(chunk).unwrap();
            }
            stream.flush().unwrap(); // Important: flush after all chunks
            None
        };
        end_timer!(timer);
        r
    }

    /// All parties send bytes to the king.
    /// Takes the bytes to send to the king.
    /// Returns the bytes received from each party if you're the king, or `None` if you're not.
    pub fn all_send_bytes_to_king(&mut self, bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
        self.all_send_bytes_to_party_sequential(0, bytes)
    }

    /// All parties recv bytes from party `sender`.
    /// Provide bytes iff you're the sender.
    /// Returns the bytes received from the sender.
    // pub fn all_recv_bytes_from_party(
    //     &mut self,
    //     sender: PartyId,
    //     bytes: Option<Vec<Vec<u8>>>,
    // ) -> Vec<u8> {
    //     let own_id = self.id;
    //     self.stats.n_from_sender += 1;
    //     if self.id == sender {
    //         let bytes = bytes.unwrap();
    //         let m = bytes[0].len();
    //         let timer = start_timer!(|| format!("From king {}", m));
    //         let bytes_size = (m as u64).to_le_bytes();
    //         self.stats.bytes_sent += (self.peers.len() - 1) * (m + 8);
    //         self.peers
    //             .par_iter_mut()
    //             .enumerate()
    //             .filter(|p| p.0 != own_id)
    //             .for_each(|(id, peer)| {
    //                 let stream = peer.stream.as_mut().unwrap();
    //                 assert_eq!(bytes[id].len(), m);
    //                 stream.write_all(&bytes_size).unwrap();
    //                 stream.write_all(&bytes[id]).unwrap();
    //             });
    //         end_timer!(timer);
    //         bytes[own_id].clone()
    //     } else {
    //         let stream = self.peers[sender].stream.as_mut().unwrap();
    //         let mut bytes_size = [0u8; 8];
    //         stream.read_exact(&mut bytes_size).unwrap();
    //         let m = u64::from_le_bytes(bytes_size) as usize;
    //         self.stats.bytes_recv += m;
    //         let mut bytes_in = vec![0u8; m];
    //         stream.read_exact(&mut bytes_in).unwrap();
    //         bytes_in
    //     }
    // }

    /// All parties recv bytes from party `sender` sequentially.
    /// Provide bytes iff you're the sender.
    /// Returns the bytes received from the sender.
    /// This is slower than the parallel version but ensures synchronization if the protocol is not constant round (e.g. iterative).
    pub fn all_recv_bytes_from_party_sequential(
        &mut self,
        sender: PartyId,
        bytes: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        let own_id = self.id;

        // For extra safety, can uncomment the ready signal here to ensure that each call here is synchronized.
        // let ready_signal = [0u8; 1];
        // for id in 0..self.peers.len() {
        //     if id != own_id {
        //         let stream = self.peers[id].stream.as_mut().unwrap();
        //         stream.write_all(&ready_signal).unwrap();
        //         stream.read_exact(&mut [0u8; 1]).unwrap();
        //     }
        // }

        self.stats.n_from_sender += 1;
        if self.id == sender {
            let bytes = bytes.unwrap();
            let m = bytes[0].len();
            let timer = start_timer!(|| format!("From king {}", m));
            let bytes_size = (m as u64).to_le_bytes();
            self.stats.bytes_sent += (self.peers.len() - 1) * (m + 8);
            self.peers
                .iter_mut()
                .enumerate()
                .filter(|p| p.0 != own_id)
                .for_each(|(id, peer)| {
                    let stream = peer.stream.as_mut().unwrap();
                    assert_eq!(bytes[id].len(), m);
                    stream.write_all(&bytes_size).unwrap();
                    stream.write_all(&bytes[id]).unwrap();
                });
            end_timer!(timer);
            bytes[own_id].clone()
        } else {
            let stream = self.peers[sender].stream.as_mut().unwrap();
            let mut bytes_size = [0u8; 8];
            stream.read_exact(&mut bytes_size).unwrap();
            let m = u64::from_le_bytes(bytes_size) as usize;
            self.stats.bytes_recv += m;
            let mut bytes_in = vec![0u8; m];
            stream.read_exact(&mut bytes_in).unwrap();
            bytes_in
        }
    }

    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king.
    /// Returns the bytes received from the king.
    pub fn all_recv_bytes_from_king(&mut self, bytes: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        self.all_recv_bytes_from_party_sequential(0, bytes)
    }

    /// Everyone sends bytes to the king, who recieves those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`.
    #[inline]
    pub fn king_compute_bytes(
        &mut self,
        bytes: &[u8],
        f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let king_response = self.all_send_bytes_to_king(bytes).map(f);
        self.all_recv_bytes_from_king(king_response)
    }

    /// Party sends bytes to party `recipient` unidirectionally.
    pub fn send_bytes_to_party(&mut self, recipient: PartyId, bytes: &[u8]) {
        assert_ne!(recipient, self.id, "cannot send bytes to same party");
        let timer = start_timer!(|| format!("To recipient {}: {} bytes", recipient, bytes.len()));
        let m = bytes.len();
        self.stats.me_to_recipient += 1;

        self.stats.bytes_sent += m + 8;
        let stream = self.peers[recipient].stream.as_mut().unwrap();
        let bytes_size = (m as u64).to_le_bytes();
        stream.write_all(&bytes_size).unwrap();
        stream.write_all(bytes).unwrap();

        end_timer!(timer);
    }

    /// Party receives bytes from party `sender` unidirectionally.
    pub fn recv_bytes_from_party(&mut self, sender: PartyId) -> Vec<u8> {
        assert_ne!(sender, self.id, "cannot receive bytes from same party");
        let timer = start_timer!(|| format!("From sender {}: receiving bytes", sender));
        self.stats.me_from_sender += 1;

        let stream = self.peers[sender].stream.as_mut().unwrap();
        let mut bytes_size = [0u8; 8];
        stream.read_exact(&mut bytes_size).unwrap();
        let m = u64::from_le_bytes(bytes_size) as usize;

        self.stats.bytes_recv += m;
        let mut bytes_in = vec![0u8; m];
        stream.read_exact(&mut bytes_in).unwrap();

        end_timer!(timer);
        bytes_in
    }
}

/// Typed communication methods, using [ark_serialize].
impl Net {
    /// Broadcast a value to all parties.
    /// See [Self::broadcast_bytes].
    /// This is the typed version.
    pub fn broadcast<T: CanonicalDeserialize + CanonicalSerialize>(&mut self, out: &T) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.broadcast_bytes_sequential(&bytes_out);
        let result = bytes_in
            .into_iter()
            .map(|b| T::deserialize_compressed(&b[..]).unwrap())
            .collect();
        result
    }

    /// Broadcast a vector of values to all parties in parallel.
    /// See [Self::broadcast_bytes].
    /// This is the typed version.
    pub fn broadcast_vector<T: CanonicalDeserialize + CanonicalSerialize + Send + Sync>(
        &mut self,
        out: &Vec<T>,
    ) -> Vec<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.broadcast_bytes_sequential(&bytes_out);
        bytes_in
            .into_par_iter()
            .map(|b| Vec::<T>::deserialize_compressed(&b[..]).unwrap())
            .collect()
    }

    /// This party sends a value to `recipient`.
    /// See [Self::send_bytes_to_party].
    /// This is the typed version.
    pub fn send_to_party<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        recipient: PartyId,
        out: &T,
    ) {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        self.send_bytes_to_party(recipient, &bytes_out);
    }

    /// This party receives a value from `sender`.
    /// See [Self::recv_bytes_from_party].
    /// This is the typed version.
    pub fn recv_from_party<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        sender: PartyId,
    ) -> T {
        let bytes_in = self.recv_bytes_from_party(sender);
        T::deserialize_compressed(&bytes_in[..]).unwrap()
    }

    /// All parties send a value to `recipient`.
    /// See [Self::all_send_bytes_to_party].
    /// This is the typed version.
    pub fn all_send_to_party<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        recipient: PartyId,
        out: &T,
    ) -> Option<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        self.all_send_bytes_to_party_sequential(recipient, &bytes_out)
            .map(|bytes_in| {
                bytes_in
                    .into_iter()
                    .map(|b| T::deserialize_compressed(&b[..]).unwrap())
                    .collect()
            })
    }

    /// All parties send a value to the king.
    /// See [Self::all_send_bytes_to_king].
    /// This is the typed version.
    pub fn all_send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        out: &T,
    ) -> Option<Vec<T>> {
        self.all_send_to_party(0, out)
    }

    /// All parties send a vector of values to `recipient` in parallel.
    /// See [Self::all_send_bytes_to_party].
    /// This is the typed version that works with vectors.
    pub fn all_send_vector_to_party<T: CanonicalDeserialize + CanonicalSerialize + Send + Sync>(
        &mut self,
        recipient: PartyId,
        out: &Vec<T>,
    ) -> Option<Vec<Vec<T>>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        self.all_send_bytes_to_party_sequential(recipient, &bytes_out)
            .map(|bytes_in| {
                bytes_in
                    .into_par_iter()
                    .map(|b| Vec::<T>::deserialize_compressed(&b[..]).unwrap())
                    .collect()
            })
    }

    /// All parties send a vector of values to the king in parallel.
    /// See [Self::all_send_bytes_to_king].
    /// This is the typed version that works with vectors.
    pub fn all_send_vector_to_king<T: CanonicalDeserialize + CanonicalSerialize + Send + Sync>(
        &mut self,
        out: &Vec<T>,
    ) -> Option<Vec<Vec<T>>> {
        self.all_send_vector_to_party(0, out)
    }

    /// All parties receive a value from the `sender`.
    /// See [Self::all_recv_bytes_from_party].
    /// This is the typed version.
    pub fn all_recv_from_party<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        sender: PartyId,
        out: Option<Vec<T>>,
    ) -> T {
        let bytes_in = self.all_recv_bytes_from_party_sequential(
            sender,
            out.map(|outs| {
                outs.iter()
                    .map(|out| {
                        let mut bytes_out = Vec::new();
                        out.serialize_compressed(&mut bytes_out).unwrap();
                        bytes_out
                    })
                    .collect()
            }),
        );
        T::deserialize_compressed(&bytes_in[..]).unwrap()
    }

    /// All parties receive a vector of values from the `sender` in parallel.
    /// See [Self::all_recv_bytes_from_party].
    /// This is the typed version that works with vectors.
    pub fn all_recv_vector_from_party<
        T: CanonicalDeserialize + CanonicalSerialize + Send + Sync,
    >(
        &mut self,
        sender: PartyId,
        out: Option<Vec<Vec<T>>>,
    ) -> Vec<T> {
        let bytes_in = self.all_recv_bytes_from_party_sequential(
            sender,
            out.map(|outs| {
                outs.into_par_iter()
                    .map(|out| {
                        let mut bytes_out = Vec::new();
                        out.serialize_compressed(&mut bytes_out).unwrap();
                        bytes_out
                    })
                    .collect()
            }),
        );
        Vec::<T>::deserialize_compressed(&bytes_in[..]).unwrap()
    }

    /// All parties receive a value from the king.
    /// See [Self::all_recv_bytes_from_party].
    /// This is the typed version.
    pub fn recv_from_king<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        out: Option<Vec<T>>,
    ) -> T {
        self.all_recv_from_party(0, out)
    }

    /// All parties receive a vector of values from the king in parallel.
    /// See [Self::all_recv_bytes_from_party].
    /// This is the typed version that works with vectors.
    pub fn all_recv_vector_from_king<T: CanonicalDeserialize + CanonicalSerialize + Send + Sync>(
        &mut self,
        out: Option<Vec<Vec<T>>>,
    ) -> Vec<T> {
        self.all_recv_vector_from_party(0, out)
    }

    /// Perform a computation just on the king.
    /// See [Self::king_compute_bytes].
    /// This is the typed version.
    pub fn king_compute<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        x: &T,
        f: impl Fn(Vec<T>) -> Vec<T>,
    ) -> T {
        let king_response = self.all_send_to_king(x).map(f);
        self.recv_from_king(king_response)
    }
}

const COMMIT_RAND_BYTES: usize = 32;
type CommitHash = Sha256;

/// Cryptographic communication methods.
impl Net {
    /// Broadcast bytes to all parties, ensuring that each party chooses a value
    /// that is independent of the others.
    ///
    /// See [Self::broadcast_bytes] for a version without this security
    /// guarantee and for information about the arguments and reture value.
    ///
    /// Requires two rounds. First commitments are exchanged, then the data.
    pub fn atomic_broadcast_bytes(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut bytes_out = Vec::new();
        bytes_out.extend_from_slice(bytes);
        bytes_out.resize(bytes.len() + COMMIT_RAND_BYTES, 0);
        rand::rng().fill_bytes(&mut bytes_out[bytes.len()..]);
        let commitment = CommitHash::digest(&bytes_out);
        // exchange commitments
        let all_commits = self.broadcast_bytes_sequential(&commitment[..]);
        // exchange (data || randomness)
        let mut all_data = self.broadcast_bytes_sequential(&bytes_out);
        let self_id = self.party_id();
        for i in 0..all_commits.len() {
            if i != self_id {
                // check other commitment
                assert_eq!(&all_commits[i][..], &CommitHash::digest(&all_data[i])[..],);
            }
            let this_data_len = all_data[i].len() - COMMIT_RAND_BYTES;
            all_data[i].resize(this_data_len, 0);
        }
        all_data
    }

    /// Broadcast a value to all parties, ensuring that each party chooses a
    /// value that is independent of the others.
    ///
    /// Typed version of [Self::atomic_broadcast_bytes].
    pub fn atomic_broadcast<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        out: &T,
    ) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.atomic_broadcast_bytes(&bytes_out);
        // TODO(aozdemir): Remove deserialization of the self-value.
        bytes_in
            .into_iter()
            .map(|b| T::deserialize_compressed(&b[..]).unwrap())
            .collect()
    }

    /// Broadcast a vector of values to all parties, ensuring that each party chooses a value
    /// that is independent of the others.
    ///
    /// See [Self::atomic_broadcast_bytes] for a version without this security
    /// guarantee and for information about the arguments and return value.
    pub fn atomic_broadcast_vector<T: CanonicalDeserialize + CanonicalSerialize + Send + Sync>(
        &mut self,
        out: &Vec<T>,
    ) -> Vec<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.atomic_broadcast_bytes(&bytes_out);
        bytes_in
            .into_par_iter()
            .map(|b| Vec::<T>::deserialize_compressed(&b[..]).unwrap())
            .collect()
    }
}

/// Tests
#[cfg(test)]
pub mod test {
    use super::*;
    use rand::Rng;
    use tempfile::NamedTempFile;

    #[test]
    fn two_parties() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                assert_eq!(net.party_id(), 0);
                assert_eq!(net.n_parties(), 2);

                let bytes0 = vec![1u8, 2, 3];
                let bytes1 = vec![4u8, 5, 6];

                let r = net.broadcast_bytes_sequential(&bytes0);
                assert_eq!(r[0], bytes0);
                assert_eq!(r[1], bytes1);
                assert_eq!(net.stats().bytes_sent, 3);
                assert_eq!(net.stats().bytes_recv, 3);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_bytes_to_king(&bytes0);
                assert_eq!(r.unwrap(), vec![bytes0.clone(), bytes1.clone()]);
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.all_recv_bytes_from_king(Some(vec![bytes1.clone(), bytes0.clone()]));
                assert_eq!(r, bytes1);
                assert_eq!(net.stats().n_from_sender, 1);
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                assert_eq!(net.party_id(), 1);
                assert_eq!(net.n_parties(), 2);

                let bytes0 = vec![1u8, 2, 3];
                let bytes1 = vec![4u8, 5, 6];

                let r = net.broadcast_bytes_sequential(&bytes1);
                assert_eq!(r[0], bytes0);
                assert_eq!(r[1], bytes1);
                assert_eq!(net.stats().bytes_sent, 3);
                assert_eq!(net.stats().bytes_recv, 3);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_bytes_to_king(&bytes1);
                assert!(r.is_none());
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.all_recv_bytes_from_king(Some(vec![bytes1.clone(), bytes0.clone()]));
                assert_eq!(r, bytes0);
                assert_eq!(net.stats().n_from_sender, 1);
            });
        });
    }

    #[test]
    fn unidirectional_send_recv_bytes() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let bytes0 = vec![1u8, 2, 3];
        let bytes1 = vec![4u8, 5, 6, 7u8, 8u8];
        let bytes0_clone = bytes0.clone();
        let bytes1_clone = bytes1.clone();

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                assert_eq!(net.party_id(), 0);
                assert_eq!(net.n_parties(), 2);

                net.send_bytes_to_party(1, &bytes0);
                assert_eq!(net.stats().bytes_sent, 3 + 8);
                assert_eq!(net.stats().bytes_recv, 0);
                assert_eq!(net.stats().me_to_recipient, 1);

                let r = net.recv_bytes_from_party(1);
                assert_eq!(net.stats().bytes_recv, 5);
                assert_eq!(r, bytes1_clone);
                assert_eq!(net.stats().me_from_sender, 1);
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                assert_eq!(net.party_id(), 1);
                assert_eq!(net.n_parties(), 2);

                net.send_bytes_to_party(0, &bytes1);
                assert_eq!(net.stats().bytes_sent, 5 + 8);
                assert_eq!(net.stats().bytes_recv, 0);
                assert_eq!(net.stats().me_to_recipient, 1);

                let r = net.recv_bytes_from_party(0);
                assert_eq!(net.stats().bytes_recv, 3);
                assert_eq!(r, bytes0_clone);
                assert_eq!(net.stats().me_from_sender, 1);
            });
        });
    }

    #[test]
    fn unidirectional_send_recv_typed() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let data0 = 8u64;
        let data0b = 10u32;
        let data1 = 16u8;

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                assert_eq!(net.party_id(), 0);
                assert_eq!(net.n_parties(), 2);

                net.send_to_party(1, &data0);
                assert_eq!(net.stats().bytes_sent, 8 + 8);
                assert_eq!(net.stats().bytes_recv, 0);
                assert_eq!(net.stats().me_to_recipient, 1);

                net.send_to_party(1, &data0b);
                assert_eq!(net.stats().bytes_sent, (8 + 8) + (8 + 4));
                assert_eq!(net.stats().bytes_recv, 0);
                assert_eq!(net.stats().me_to_recipient, 2);

                let r: u8 = net.recv_from_party(1);
                assert_eq!(net.stats().bytes_recv, 1);
                assert_eq!(r, data1);
                assert_eq!(net.stats().me_from_sender, 1);
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                assert_eq!(net.party_id(), 1);
                assert_eq!(net.n_parties(), 2);

                net.send_to_party(0, &data1);
                assert_eq!(net.stats().bytes_sent, 1 + 8);
                assert_eq!(net.stats().bytes_recv, 0);
                assert_eq!(net.stats().me_to_recipient, 1);

                let r: u64 = net.recv_from_party(0);
                assert_eq!(net.stats().bytes_recv, 8);
                assert_eq!(r, data0);
                assert_eq!(net.stats().me_from_sender, 1);

                let r: u32 = net.recv_from_party(0);
                assert_eq!(net.stats().bytes_recv, 8 + 4);
                assert_eq!(r, data0b);
                assert_eq!(net.stats().me_from_sender, 2);
            });
        });
    }

    #[test]
    // the same test, but with non-byte data.
    fn two_parties_typed() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                assert_eq!(net.party_id(), 0);
                assert_eq!(net.n_parties(), 2);

                let data0 = 8u64;
                let data1 = 16u64;

                let r = net.broadcast(&data0);
                assert_eq!(r[0], data0);
                assert_eq!(r[1], data1);
                assert_eq!(net.stats().bytes_sent, 8);
                assert_eq!(net.stats().bytes_recv, 8);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_to_king(&data0);
                assert_eq!(r.unwrap(), vec![data0.clone(), data1.clone()]);
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.recv_from_king(Some(vec![data1.clone(), data0.clone()]));
                assert_eq!(r, data1);
                assert_eq!(net.stats().n_from_sender, 1);
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                assert_eq!(net.party_id(), 1);
                assert_eq!(net.n_parties(), 2);

                let data0 = 8u64;
                let data1 = 16u64;

                let r = net.broadcast(&data1);
                assert_eq!(r[0], data0);
                assert_eq!(r[1], data1);
                assert_eq!(net.stats().bytes_sent, 8);
                assert_eq!(net.stats().bytes_recv, 8);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_to_king(&data1);
                assert!(r.is_none());
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.recv_from_king(Some(vec![data1.clone(), data0.clone()]));
                assert_eq!(r, data0);
                assert_eq!(net.stats().n_from_sender, 1);
            });
        });
    }

    #[test]
    fn two_parties_vector_typed() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                assert_eq!(net.party_id(), 0);
                assert_eq!(net.n_parties(), 2);

                let data0 = vec![8u64, 9, 10];
                let data1 = vec![16u64, 17, 18];

                let r = net.broadcast_vector(&data0);
                assert_eq!(r[0], data0);
                assert_eq!(r[1], data1);
                assert_eq!(net.stats().bytes_sent, 32);
                assert_eq!(net.stats().bytes_recv, 32);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_vector_to_king(&data0);
                assert_eq!(r.unwrap(), vec![data0.clone(), data1.clone()]);
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.all_recv_vector_from_king(Some(vec![data1.clone(), data0.clone()]));
                assert_eq!(r, data1);
                assert_eq!(net.stats().n_from_sender, 1);
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                assert_eq!(net.party_id(), 1);
                assert_eq!(net.n_parties(), 2);

                let data0 = vec![8u64, 9, 10];
                let data1 = vec![16u64, 17, 18];

                let r = net.broadcast_vector(&data1);
                assert_eq!(r[0], data0);
                assert_eq!(r[1], data1);
                assert_eq!(net.stats().bytes_sent, 32);
                assert_eq!(net.stats().bytes_recv, 32);
                assert_eq!(net.stats().n_broadcasts, 1);

                let r = net.all_send_vector_to_king(&data1);
                assert!(r.is_none());
                assert_eq!(net.stats().n_to_recipient, 1);

                let r = net.all_recv_vector_from_king(Some(vec![data1.clone(), data0.clone()]));
                assert_eq!(r, data0);
                assert_eq!(net.stats().n_from_sender, 1);
            });
        });
    }
}
