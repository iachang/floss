use crate::arithcircop::{ArithCircState, AuthTriple, UnauthTriple};
use crate::arithcircprep::ArithCircPrep;
use crate::net::Net;
use crate::primitives::auth::AuthShare;
use ark_ff::{Field, PrimeField};

use byteorder::{LittleEndian, ReadBytesExt};
use regex::Regex;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};

/// Minimum number of triples per thread to switch from MASCOT to LowGear
pub static MIN_TRIPLES_PER_THREAD: usize = 800000;

/// Whether the program is running in alone mode
pub fn is_alone() -> bool {
    std::env::var("ALONE")
        .map(|v| !(v == "false"))
        .unwrap_or(true)
}

/// Maximum number of threads to use for SPDZ
pub fn max_threads() -> usize {
    if is_alone() { 4 } else { 22 }
}

/// Generate preprocessing using MP-SPDZ
pub struct SPDZArithCircPrep<F: Field + PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field + PrimeField> SPDZArithCircPrep<F> {
    /// Create a new SPDZ preprocessing instance
    pub fn new() -> Self {
        SPDZArithCircPrep {
            _phantom: std::marker::PhantomData,
        }
    }

    #[allow(dead_code)]
    fn read_u64_le<R: Read>(r: &mut R) -> io::Result<u64> {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    #[allow(dead_code)]
    fn read_u32_le<R: Read>(r: &mut R) -> io::Result<u32> {
        let mut b = [0u8; 4];
        r.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_mpspdz_header<R: Read>(r: &mut R) -> io::Result<u128> {
        let hdr_len = r.read_u64::<LittleEndian>()?;
        let mut buf = vec![0u8; hdr_len as usize];
        r.read_exact(&mut buf)?;

        let mut buf_reader = std::io::Cursor::new(&buf);

        // Skip protocol descriptor "SPDZ gfp" (8 bytes)
        buf_reader.set_position(8);

        // Read sign byte
        let mut sign = [0u8; 1];
        buf_reader.read_exact(&mut sign)?;
        if sign[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected sign byte: {}", sign[0]),
            ));
        }

        // Read prime length
        let prime_len = buf_reader.read_u32::<LittleEndian>()? as usize;
        if prime_len == 0 || prime_len > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("suspicious prime length: {}", prime_len),
            ));
        }

        // Read prime (big-endian)
        let mut prime_be = vec![0u8; prime_len];
        buf_reader.read_exact(&mut prime_be)?;

        let prime = u128::from_be_bytes(prime_be.try_into().unwrap());

        // Continue reading the u64 that was there before
        buf_reader.read_u64::<LittleEndian>()?;

        Ok(prime)
    }

    fn _extract_mpspdz_header<R: Read>(r: &mut R) -> io::Result<()> {
        // 1) header length (not strictly needed, but good sanity)
        let _len_to_follow = Self::read_u64_le(r)?;

        // 2) protocol descriptor
        let mut proto = [0u8; 8];
        r.read_exact(&mut proto)?;
        if &proto != b"SPDZ gfp" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected protocol descriptor: {:?}",
                    String::from_utf8_lossy(&proto)
                ),
            ));
        }

        // 3) domain descriptor: sign + length + prime (big-endian)
        let mut sign = [0u8; 1];
        r.read_exact(&mut sign)?;
        if sign[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected sign byte: {}", sign[0]),
            ));
        }

        let prime_len = Self::read_u32_le(r)? as usize;
        if prime_len == 0 || prime_len > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("suspicious prime length: {}", prime_len),
            ));
        }

        let mut prime_be = vec![0u8; prime_len];
        r.read_exact(&mut prime_be)?;

        let _prime = u128::from_be_bytes(prime_be.try_into().unwrap());

        Ok(())
    }
    fn rinv() -> F {
        // R = 2^(64*K).
        // pow exponent is little-endian u64 limbs.
        let num_bits = ((F::MODULUS_BIT_SIZE + 7) / 8) * 8;
        let r = F::from(2u64).pow([num_bits as u64]);
        r.inverse().unwrap()
    }

    fn read_mpspdz_gfp_k2<R: Read>(r: &mut R, r_inv: &F) -> io::Result<F> {
        // MP-SPDZ stores xR mod p as an integer (Montgomery form).
        let num_modulus_bytes = ((F::MODULUS_BIT_SIZE + 7) / 8) as usize;

        let mut bytes = vec![0u8; num_modulus_bytes];
        r.read_exact(&mut bytes)?;

        let x_r = F::from_le_bytes_mod_order(&bytes);
        Ok(x_r * r_inv)
    }

    /// Generate auth triples, unauth triples, and auth coins from the given path
    pub fn generate_triples_and_auth_coins(
        num_auth_triples: usize,
        num_unauth_triples: usize,
        num_auth_coins: usize,
        paths: &[String],
    ) -> io::Result<(Vec<AuthTriple<F>>, Vec<UnauthTriple<F>>, Vec<AuthShare<F>>)> {
        let mut auth_triples_out = Vec::<AuthTriple<F>>::new();
        let mut unauth_triples_out = Vec::<UnauthTriple<F>>::new();
        let mut coins_out = Vec::<AuthShare<F>>::new();

        for path in paths {
            let f = File::open(path)?;
            let mut r = BufReader::new(f);
            println!("Reading from file: {}", path);

            // 1) header
            let prime = Self::read_mpspdz_header(&mut r)?;
            dbg!("Prime: {}", prime);
            let r_inv = Self::rinv();

            // 2) body: repeat (a,mac_a), (b,mac_b), (c,mac_c) until EOF
            while auth_triples_out.len() < num_auth_triples {
                let a = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let mac_a = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let b = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let mac_b = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let c = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let mac_c = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };

                auth_triples_out.push((
                    AuthShare {
                        value: a,
                        mac: mac_a,
                    },
                    AuthShare {
                        value: b,
                        mac: mac_b,
                    },
                    AuthShare {
                        value: c,
                        mac: mac_c,
                    },
                ));
            }

            while unauth_triples_out.len() < num_unauth_triples {
                let a = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let _mac_a = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let b = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let _mac_b = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let c = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let _mac_c = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };

                unauth_triples_out.push((a, b, c));
            }

            while coins_out.len() < num_auth_coins {
                let coin = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };
                let mac_coin = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                    Ok(v) => v,
                    Err(_e) => break,
                };

                coins_out.push(AuthShare {
                    value: coin,
                    mac: mac_coin,
                });
            }
        }

        if auth_triples_out.len() < num_auth_triples
            || unauth_triples_out.len() < num_unauth_triples
            || coins_out.len() < num_auth_coins
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected {} auth triples, {} unauth triples, and {} auth coins, only got {} auth triples, {} unauth triples, and {} auth coins",
                    num_auth_triples,
                    num_unauth_triples,
                    num_auth_coins,
                    auth_triples_out.len(),
                    unauth_triples_out.len(),
                    coins_out.len(),
                ),
            ));
        }
        Ok((auth_triples_out, unauth_triples_out, coins_out))
    }

    /// Generate auth coins
    pub fn generate_auth_coins(path: &str) -> io::Result<Vec<AuthShare<F>>> {
        let f = File::open(path)?;
        let mut r = BufReader::new(f);

        // 1) header
        Self::read_mpspdz_header(&mut r)?;
        let r_inv = Self::rinv();

        // 2) body: repeat (coin,mac_coin) until EOF
        let mut out = Vec::<AuthShare<F>>::new();
        loop {
            let coin = match Self::read_mpspdz_gfp_k2(&mut r, &r_inv) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            let mac_coin = Self::read_mpspdz_gfp_k2(&mut r, &r_inv)?;

            out.push(AuthShare {
                value: coin,
                mac: mac_coin,
            });
        }

        Ok(out)
    }

    /// Get the SPDZ key from the given path
    pub fn get_spdz_key(path: &str) -> Result<F, String> {
        let txt = fs::read_to_string(path).unwrap();
        let mut lines = txt.lines().map(str::trim).filter(|l| !l.is_empty());

        // 1) Skip the first non-empty line ("2")
        lines.next().ok_or("missing first line").unwrap();

        // 2) Read second non-empty line (the decimal number)
        let mac_dec = lines.next().ok_or("missing MAC key line").unwrap();

        // 3) Parse as a field element (decimal)
        F::from_str(mac_dec).map_err(|_| "failed to parse field element".to_string())
    }
}

use std::{
    collections::HashSet,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

fn _list_player_data_dirs() -> io::Result<HashSet<PathBuf>> {
    let mut set = HashSet::new();
    let base = Path::new("./mp-spdz-0.4.2/Player-Data");
    if !base.exists() {
        return Ok(set);
    }
    for entry in fs::read_dir(base)? {
        let p = entry?.path();
        if p.is_dir() {
            if let Some(name) = p.file_name().and_then(OsStr::to_str) {
                if name.starts_with("2-p-") {
                    set.insert(p);
                }
            }
        }
    }
    Ok(set)
}

fn _newest_created_dir(_before: &HashSet<PathBuf>) -> io::Result<PathBuf> {
    let after = _list_player_data_dirs()?;
    // let mut new_dirs: Vec<PathBuf> = after.difference(before).cloned().collect();
    let mut new_dirs: Vec<PathBuf> = after.into_iter().collect();

    if new_dirs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No new Player-Data/2-p-* directory was created",
        ));
    }

    // Pick the newest by metadata mtime
    new_dirs.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
    Ok(new_dirs.last().unwrap().clone())
}

fn parse_file_location_from_stderr(stderr: &str) -> Option<String> {
    // Look for the pattern "Writing to file in {path}"
    let prefix = "Writing to file in ";
    if let Some(start) = stderr.find(prefix) {
        let path_start = start + prefix.len();
        // Extract until newline
        if let Some(end) = stderr[path_start..].find('\n') {
            return Some(stderr[path_start..path_start + end].trim().to_string());
        } else {
            // No newline, take rest of string
            return Some(stderr[path_start..].trim().to_string());
        }
    }
    None
}

fn run_mascot_gen(
    prime_dec: &str,
    num_triples: usize,
    party: u32,
    host_name: &str,
    base_port: u32,
) -> io::Result<(String, f64)> {
    let recrafted_prime = u128::from(2 as u32).pow(127) + 55 * u128::from(2 as u32).pow(15) + 1;
    dbg!("Recrafted prime: {}, prime: {}", recrafted_prime, prime_dec);

    let compile_circ = Command::new("./compile.py")
        .current_dir("mp-spdz-0.4.2")
        .args(["Programs/Source/fuel.mpc", num_triples.to_string().as_str()])
        .status()?;

    if compile_circ.code().unwrap_or(-1) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "compile.py failed: exit={}",
                compile_circ.code().unwrap_or(-1)
            ),
        ));
    }

    let program = format!("fuel-{}", num_triples);

    let status = Command::new("./mascot-offline.x")
        .current_dir("mp-spdz-0.4.2")
        .args([
            "-N",
            "2",
            "-p",
            &party.to_string(),
            "-h",
            host_name,
            "-pn",
            &base_port.to_string(),
            "-P",
            prime_dec,
            &program,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    // Check exit status - benchmark output only appears on successful completion
    let exit_code = status.status.code().unwrap_or(-1);

    if exit_code != 0 {
        let stderr_preview = String::from_utf8_lossy(&status.stderr);
        let stdout_preview = String::from_utf8_lossy(&status.stdout);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "mascot-offline.x failed with exit code {}.\nStderr: {}\nStdout: {}",
                exit_code, stderr_preview, stdout_preview
            ),
        ));
    }

    let stderr = String::from_utf8_lossy(&status.stderr);
    dbg!("Exit code: {}", &stderr);
    let dir = parse_file_location_from_stderr(&stderr).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "Failed to parse file location from stderr",
        )
    })?;

    let combined = format!("{}{}", String::from_utf8_lossy(&status.stdout), stderr);

    // Parse benchmark output - these are printed to stderr (cerr) at the end of execution
    let time_re = Regex::new(r"Time\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*seconds").unwrap();
    let data_sent_re = Regex::new(r"Data sent\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*MB").unwrap();

    if let Some(caps) = time_re.captures(&combined) {
        let _time: f64 = caps[1].parse().unwrap();
    }

    if let Some(caps) = data_sent_re.captures(&combined) {
        let gb: f64 = caps[1].parse::<f64>().unwrap() / 1024.0;
        Ok((dir, gb))
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to parse data sent from stderr",
        ))
    }
}

fn run_lowgear_gen(
    num_triples: usize,
    party: u32,
    host_name: &str,
    base_port: u32,
) -> io::Result<(String, f64)> {
    let num_threads: usize = if num_triples / MIN_TRIPLES_PER_THREAD > max_threads() {
        max_threads()
    } else {
        num_triples / MIN_TRIPLES_PER_THREAD
    };
    dbg!("Number of threads: {}", num_threads);

    let status = Command::new("./pairwise-offline.x")
        .current_dir("mp-spdz-0.4.2")
        .args([
            "-N",
            "2",
            "-p",
            &party.to_string(),
            "-h",
            host_name,
            "-pn",
            &base_port.to_string(),
            "-x",
            &num_threads.to_string(),
            "--ntriples",
            &num_triples.to_string(),
            "-o",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    // Check exit status - benchmark output only appears on successful completion
    let exit_code = status.status.code().unwrap_or(-1);
    if exit_code != 0 {
        let stderr_preview = String::from_utf8_lossy(&status.stderr);
        let stdout_preview = String::from_utf8_lossy(&status.stdout);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "pairwise-offline.x failed with exit code {}.\nStderr: {}\nStdout: {}",
                exit_code, stderr_preview, stdout_preview
            ),
        ));
    }

    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);

    let combined = format!("{}\n{}", stdout, stderr);
    println!("StdOut + Stderr: {}", combined);

    let dir = parse_file_location_from_stderr(&combined).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "Failed to parse file location from stderr",
        )
    })?;

    // Parse benchmark output - these are printed to stderr (cerr) at the end of execution
    let data_sent_gb_re = Regex::new(r"Sent\s+([0-9]+(?:\.[0-9]+)?)\s+GB\s+in\s+total").unwrap();

    if let Some(caps) = data_sent_gb_re.captures(&combined) {
        let gb: f64 = caps[1].parse().unwrap();
        Ok((dir, gb))
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to parse data sent from stderr",
        ))
    }
}

fn run_one_party(
    prime_dec: &str,
    num_triples: usize,
    party: u32,
    host_name: &str,
    base_port: u32,
) -> io::Result<(String, f64)> {
    if num_triples > MIN_TRIPLES_PER_THREAD {
        dbg!("Running LowGear offline phase");
        return run_lowgear_gen(num_triples, party, host_name, base_port);
    } else {
        dbg!("Running Mascot offline phase");
        return run_mascot_gen(prime_dec, num_triples, party, host_name, base_port);
    }
}

/// Find the total number of triples needed in MP-SPDZ
pub fn find_total_triples(
    num_auth_triples: usize,
    num_unauth_triples: usize,
    num_auth_coins: usize,
) -> usize {
    num_auth_triples + num_unauth_triples + num_auth_coins * 1 / 3 + 1
}

/// Run the Mascot offline phase and get the directory of the new Player-Data
pub fn run_mascot_offline_and_get_dir<F: Field + PrimeField>(
    net: &mut Net,
    num_auth_triples: usize,
    num_unauth_triples: usize,
    num_auth_coins: usize,
) -> io::Result<PathBuf> {
    // 2) run both parties concurrently
    let party = net.party_id();
    let host_name = net.get_host_ip();
    let prime0 = F::MODULUS.to_string();

    dbg!(
        "Running offline phase",
        find_total_triples(num_auth_triples, num_unauth_triples, num_auth_coins)
    );
    let t0 = thread::spawn(move || {
        run_one_party(
            &prime0,
            find_total_triples(num_auth_triples, num_unauth_triples, num_auth_coins),
            party as u32,
            host_name.as_str(),
            5101,
        )
    });

    // 3) find the new Player-Data directory
    let (dir_name, communication_gb) = t0.join().unwrap()?;
    let dir = "./mp-spdz-0.4.2/".to_string() + &dir_name;
    let communication_bytes = (communication_gb * 1024.0 * 1024.0 * 1024.0) as usize;
    net.add_communication_cost(communication_bytes);
    // 4) sanity check key files exist
    let triples0 = PathBuf::from(dir.clone()).join(format!("Triples-p-P{}", party));

    if !triples0.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Expected triples files not found in {}",
                PathBuf::from(dir).display()
            ),
        ));
    }

    Ok(PathBuf::from(dir))
}

impl<F: Field + PrimeField> ArithCircPrep<F> for SPDZArithCircPrep<F> {
    fn run(
        &mut self,
        net: &mut Net,
        _n_unauth_coins: usize,
        n_auth_coins: usize,
        n_unauth_triples: usize,
        n_auth_triples: usize,
        _n_inversions: usize,
    ) -> ArithCircState<F> {
        let party = net.party_id();

        let dir = run_mascot_offline_and_get_dir::<F>(
            net,
            n_auth_triples,
            n_unauth_triples,
            n_auth_coins,
        )
        .unwrap();

        let key = Self::get_spdz_key(
            &dir.join(format!("Player-MAC-Keys-p-P{party}"))
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let mut state = ArithCircState::new(key);

        let num_triples = find_total_triples(n_auth_triples, n_unauth_triples, n_auth_coins);
        let num_threads: usize = if num_triples / MIN_TRIPLES_PER_THREAD > max_threads() {
            max_threads()
        } else {
            num_triples / MIN_TRIPLES_PER_THREAD
        };

        let paths = if find_total_triples(n_auth_triples, n_unauth_triples, n_auth_coins)
            > MIN_TRIPLES_PER_THREAD
        {
            (0..num_threads)
                .map(|i| {
                    if i == 0 {
                        dir.join(format!("Triples-p-P{party}"))
                            .to_str()
                            .unwrap()
                            .to_string()
                    } else {
                        dir.join(format!("Triples-p-P{party}-{i}"))
                            .to_str()
                            .unwrap()
                            .to_string()
                    }
                })
                .collect()
        } else {
            vec![
                dir.join(format!("Triples-p-P{party}"))
                    .to_str()
                    .unwrap()
                    .to_string(),
            ]
        };

        let (triples, unauth_triples, coins) = Self::generate_triples_and_auth_coins(
            n_auth_triples,
            n_unauth_triples,
            n_auth_coins,
            &paths,
        )
        .unwrap();
        state.add_triples(triples);
        state.add_unauth_triples(unauth_triples);
        state.add_auth_coins(coins);
        state
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::arithcircprep::{ArithCircPrep, spdz::SPDZArithCircPrep};

    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::SPDZ128Fq;

    #[test]
    fn test_spdz_arith_circ_prep() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let n = 10;
        let n_auth_triples = 3 * n;
        let n_unauth_triples = 2 * n;
        let n_auth_coins = n;

        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            usize,
            Fr,
            Vec<AuthTriple<Fr>>,
            Vec<UnauthTriple<Fr>>,
            Vec<AuthShare<Fr>>,
        )>::new()));

        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = SPDZArithCircPrep::<Fr>::new().run(
                    &mut net,
                    0,
                    n_auth_coins,
                    n_unauth_triples,
                    n_auth_triples,
                    0,
                );

                // state.take_triples(1);
                let triples = state.take_triples(n_auth_triples);
                let unauth_triples = state.take_unauth_triples(n_unauth_triples);
                let coins = state.take_auth_coins(n_auth_coins);

                // Store the results for verification
                outputs_party0.lock().unwrap().push((
                    net.party_id(),
                    state.key_share(),
                    triples,
                    unauth_triples,
                    coins,
                ));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = SPDZArithCircPrep::<Fr>::new().run(
                    &mut net,
                    0,
                    n_auth_coins,
                    n_unauth_triples,
                    n_auth_triples,
                    0,
                );

                // state.take_triples(1);
                let triples = state.take_triples(n_auth_triples);
                let unauth_triples = state.take_unauth_triples(n_unauth_triples);
                let coins = state.take_auth_coins(n_auth_coins);

                // Store the results for verification
                outputs_party1.lock().unwrap().push((
                    net.party_id(),
                    state.key_share(),
                    triples,
                    unauth_triples,
                    coins,
                ));
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify that both parties got the same results
        if combined_outputs.len() == 2 {
            let party0_id = if combined_outputs[0].0 == 0 { 0 } else { 1 };

            let (_, key_share0, triples0, unauth_triples0, coins0) = if party0_id == 0 {
                &combined_outputs[0]
            } else {
                &combined_outputs[1]
            };
            let (_, key_share1, triples1, unauth_triples1, coins1) = if party0_id == 0 {
                &combined_outputs[1]
            } else {
                &combined_outputs[0]
            };

            for triple in 0..triples0.len() {
                assert_eq!(
                    (triples0[triple].0.value + triples1[triple].0.value)
                        * (key_share0 + key_share1),
                    (triples0[triple].0.mac + triples1[triple].0.mac)
                );

                assert_eq!(
                    (triples0[triple].1.value + triples1[triple].1.value)
                        * (key_share0 + key_share1),
                    (triples0[triple].1.mac + triples1[triple].1.mac)
                );

                assert_eq!(
                    (triples0[triple].2.value + triples1[triple].2.value)
                        * (key_share0 + key_share1),
                    (triples0[triple].2.mac + triples1[triple].2.mac)
                );

                assert_eq!(
                    (triples0[triple].0.value + triples1[triple].0.value)
                        * (triples0[triple].1.value + triples1[triple].1.value),
                    triples0[triple].2.value + triples1[triple].2.value
                );

                assert_eq!(
                    (key_share0 + key_share1)
                        * (triples0[triple].0.value + triples1[triple].0.value)
                        * (triples0[triple].1.value + triples1[triple].1.value),
                    triples0[triple].2.mac + triples1[triple].2.mac
                );
            }

            for triple in 0..unauth_triples0.len() {
                assert_eq!(
                    (unauth_triples0[triple].0 + unauth_triples1[triple].0)
                        * (unauth_triples0[triple].1 + unauth_triples1[triple].1),
                    (unauth_triples0[triple].2 + unauth_triples1[triple].2)
                );
            }

            for coin in 0..coins0.len() {
                assert_eq!(
                    (key_share0 + key_share1) * (coins0[coin].value + coins1[coin].value),
                    coins0[coin].mac + coins1[coin].mac
                );
            }
        }
    }
}
