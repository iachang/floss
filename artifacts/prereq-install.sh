#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
ZSHRC="${HOME}/.zshrc"

echo "==> [1/6] Installing dependencies (apt + python3 prerequisites)"
sudo apt-get update -y
sudo apt-get install -y automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3 unzip python3-pip
python3 -m pip install --no-input numpy matplotlib pandas scipy latex

echo "==> [2/6] Installing Rust"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

echo "==> [3/6] Installing MP-SPDZ"
cd mp-spdz-0.4.2
chmod +x compile.py
make clean
make setup
make -j8 pairwise-offline.x mascot-offline.x lowgear-party.x mascot-party.x

echo "==> [4/6] Installing OPM"
cd ..
./scripts/setup-opmcc-bench.sh

echo "==> [5/6] Installing FLOSS"
cargo build --release

echo "==> [6/6] Done!"