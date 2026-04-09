# FLOSS (Fast Linear Online Secret-Shared Shuffle)

This Rust library provides a framework for building modular arithmetic permutation circuits in two-party computation (2PC).

## Project Structure

This repository is organized as follows:

- [artifacts/](artifacts/) — Files and scripts for generating artifacts on AWS EC2
- [OPM](opm/) — Source code files for OPM (provided by and approved to release by [Song et. al, 2023](https://eprint.iacr.org/2023/1794))
- [mp-spdz-0.4.2/Programs/Source](mp-spdz-0.4.2/Programs/Source) — MPC circuit descriptions we use to benchmark shuffling protocols and sorting protocols with MP-SPDZ, including `sort-bench.py`, `quicksort.mpc`, and `quicksort_rand.mpc`.
- [src/arithpermcircprep/mod.rs](src/arithpermcircprep/mod.rs) — Core trait definition for generating preprocessing for an arithmetic permutation circuit
- [src/arithpermcircprep/perm_network.rs](src/arithpermcircprep/perm_network.rs) — Permutation preprocessing using the [Mohassel et. al, 2014](https://eprint.iacr.org/2014/102) O(1) round malicious secure permutation network construction
- [src/arithpermcircop/simple_perm_network.rs](src/arithpermcircop/simple_perm_network.rs) — Permutation preprocessing using the O(log(n)) Waksman network construction
- [src/arithpermcircop/mod.rs](src/arithpermcircop/mod.rs) — Core trait definition for defining operations over an arithmetic permutation circuit interface
- [src/arithpermcircop/shuffle.rs](src/arithpermcircop/shuffle.rs) — One-sided permutation operation utilizing our protocol FLOSS
- [src/arithpermcircop/sort.rs](src/arithpermcircop/sort.rs) — Sort circuit description following the [Radix-Sort-and-Shuffle](https://eprint.iacr.org/2022/1595) protocol
- [benches/](benches/) — List of runnable benchmarks
- [scripts/](scripts/) — Scripts to handle dependency setup
- [plots/](plots/) — Scripts to generate and read plots

---

## Manual Installation/Build

### Prerequisites:

Install basic dependencies:

```zsh
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3 unzip

python3 -m pip install numpy matplotlib pandas scipy latex
```

Install [TexLive/MacTeX](https://tug.org/texlive/), and the necessary libraries are installed for creating plots:

```sh
sudo tlmgr update --self
sudo tlmgr install pgf
sudo tlmgr install xcolor
```

Install Rust:

```zsh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### MP-SPDZ

Compile MP-SPDZ and 2PC malicious-secure protocols:

```zsh
cd mp-spdz-0.4.2
make clean
make setup
make -j8 pairwise-offline.x mascot-offline.x lowgear-party.x mascot-party.x
```

### OPM (on Docker)

For local computation on a single machine, running OPM benchmarks on Docker are supported:

```zsh
cd OPM
docker build -t mosac:latest .
```

### OPM (on Ubuntu machine(s))

In order to run OPM benchmarks locally on an Ubuntu machine or on two Ubuntu machines (both must run Ubuntu), need to install dependencies for OPM:

```zsh
./scripts/setup-opmcc-bench.sh
```

### Computation on two machines

FLOSS support running arithmetic permutation circuits with two separate machines.

Fill in `machine_0_ip` and `machine_0_port` with the IP address and opened port of `Party 0`. Repeat `machine_1_ip` and `machine_1_port` for `Party 1`.

```zsh
cat <<EOF > parties.txt
machine_0_ip:machine_0_port
machine_1_ip:machine_1_port
EOF
```

## Tests and Benchmarks

### FLOSS Benchmarks

In our benchmark library [benches/](benches/), we support shuffle benchmarks for FLOSS, PermNet, and SimplePermNet. We also support sort benchmarks for Radix Sort parametrized by the following shuffle protocols: FLOSS, PermNet, and SimplePermNet.

By default, FLOSS and SimplePermNet use the O(log(n)) round permutation network preprocessing construction for both shuffling and sorting. PermNet uses the O(1) round Mohassel permutation network preprocessing construction.

**Run a specific benchmark on local machine:**

```zsh
cargo bench --bench <name>
```

Example:

```zsh
cargo bench --bench floss_shuffle
```

The outputs will be saved by default as `.csv` files to the project root.

**Run all benchmarks on local machine:**

```zsh
cargo bench --workspace
```

**Run a specific benchmark on two machines:**

On party 0:

```zsh
ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench perm_network_shuffle
```

On party 1:

```zsh
ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench perm_network_shuffle
```

**Run all benchmarks on two machines:**

On party 0:

```zsh
ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --workspace
```

On party 1:

```zsh
ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --workspace
```

**MP-SPDZ Baselines:**

Lastly, we support MP-SPDZ benchmarks for Quicksort and Sorting Network. The options implemented are the `Quicksort` and `Sorting Network` sorting benchmarks.

```zsh
cargo bench --bench sort_with_quicksort
cargo bench --bench sort_with_sorting_network
```

**List of implemented benchmarks:** [benches/](benches/) — one `*.rs` harness per `cargo bench --bench` name (for example `floss_shuffle.rs`).

### OPM Benchmarks

We provide an easy one-run script to benchmark OPM.

**Local Machine:**

```zsh
./scripts/bench_opmcc.sh
```

**Two machines:**

On party 0:

```zsh
./scripts/bench_opmcc.sh 0 machine_0_ip:machine_0_port,machine_1_ip:machine_1_port
```

On party 1:

```zsh
./scripts/bench_opmcc.sh 1 machine_0_ip:machine_0_port,machine_1_ip:machine_1_port
```

## Generating and Viewing Plots

The project includes Python scripts for plotting benchmark results.
Ensure that you have all required `.csv` file(s) from running the [FLOSS Benchmarks](#floss-benchmarks).

**Generate all plots (e.g. benchmarks run with two AWS instances)**

```sh
cd plots/
python3 gen_plot_data.py
pdflatex main.tex
cd .. # return to project root directory
```

**Generate partial plots (e.g. benchmarks run local in ALONE mode)**

```sh
cd plots/
python3 gen_plot_data.py --alone 1
pdflatex main.tex
cd .. # return to project root directory
```

**View generated plots**

```sh
open plots/main.pdf
```
