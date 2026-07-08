# FLOSS Artifact Evaluation:

## Reproducing Results

We provide three options for reproducing paper results. The first option is for those with AWS resources, the second option is for those with access to large local servers, and the third option is for those running on a local computer with more limited memory.

1. [Option 1 [Recommended]](#option-1) produces full benchmark plots for FLOSS (and all other baselines), but requires access to running two AWS `c5.18xlarge` instances continuously for up to 24 hours. It is a simple setup consisting of several one-run scripts.

2. [Option 2](#option-2) produces the full benchmark plots without AWS, but requires local resources comparable to two AWS `c5.18xlarge` instances. This totals to around 144 vCPUs and 288GB memory for a single local large server. This can be done with two local Ubuntu servers (each server with 72 vCPUs and 144GB memory), or with two Docker containers on a single large local server (containing 144 vCPUs and 288GB memory).

3. [Option 3](#option-3) produces subsamples of the benchmark plots for FLOSS (and all other baselines) since we assume execution on a single machine with 16GB RAM and Apple M4 chip (or similar processing power). Larger input sizes are omitted to prevent exceeding memory consumption. Therefore, the pareto plots are not reproducible in this setting.

---

<h2 id="option-1">[Option 1] Step-by-step artifact evaluation walkthrough for users with AWS Access</h2>

This is the automated way to replicate the full benchmark results of FLOSS. Provided access to AWS credentials, these one-run scripts will launch two `c5.18xlarge` instances and then run the full benchmark suite in whole.

### Part 1: Local Computer Setup

1. [3 minutes] Install [TexLive/MacTeX](https://tug.org/texlive/), and the necessary libraries are installed for creating plots:

```sh
sudo tlmgr update --self
sudo tlmgr install pgf
sudo tlmgr install xcolor
```

2. [3 minutes] Make sure python3 and the necessary libraries are installed:

```zsh
python3 -m pip install numpy matplotlib pandas scipy latex
```

3. [5 minutes] Install [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) (version 2 works) and run `aws configure` using the instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html) (use `us-west-2` as the default region, use `json` as the default output format, and your AWS credentials).

### Part 2: AWS Infrastructure Setup

4. [5 minutes] To start a cluster, run the following:

```sh
python3 artifacts/start_cluster.py
```

This will create the EC2 instances for the experiments using the correct AMI and copy configuration files to each instance.

### Part 3: Running and Retrieving Experiments

5. [~24 hours] Run the one-run script to asynchronously run all benchmarks:

```sh
python3 artifacts/run_floss_bench.py
```

There is an initial portion that will install all the dependencies and prerequisites on the AWS machines. This is synchronous (Terminal tab **must** be kept open for this initial portion), but only takes around 5-10 minutes. There may be commands that you will need to interactively accept with "Y".

Afterwards, the script will automatically launch all the benchmarks asynchronously in a `nohup` environment so at this point, the user can turn off their terminal since the benchmarks will run in the background process. The signal to close the Terminal tab is that tab is not actively running anything on the screen itself. At this point, the user should wait at least 24 hours for all benchmarks to finish before collecting them.

6. [<1 minute] Collect the raw experiment results once they are finished:

```sh
python3 artifacts/collect_floss_bench_results.py
```

7. When you are finished collecting experiment results, tear down the cluster to save resources.

```sh
python3 artifacts/teardown_cluster.py
```

### Part 4: Creating the Plots

8. Run scripts to create table results and plots:

```sh
cd plots/
python3 gen_plot_data.py
pdflatex main.tex
cd .. # return to project root directory
```

9. To view plot/table results:

**(Experiment E1) Table 1 + Individual
shuffling data**

```sh
cat plots/plot_data/shuffle_offline_time.csv
cat plots/plot_data/shuffle_online_time.csv
```

**(Experiment E2) Individual
sorting data**

```sh
cat plots/plot_data/sort_offline_time.csv
cat plots/plot_data/sort_online_time.csv
```

**(Experiment E1 + E2) Figures 7–10**

```sh
open plots/main.pdf
```

**(Experiment E1) Table 3 (in Project Root directory)**

```sh
cat shuffle_floss_offline.csv
cat shuffle_perm_network_offline.csv
```



### Common issues:

1. When running `start_cluster.py`, if you see a JSONDecodeError involving `json.loads(out)` and `raise JSONDecodeError("Expecting value", s, err.value)`, it means that the `system.config` file is missing or corrupted. In this case, download the latest `system.config` file from the `SYSTEM_CONFIG_URL` entry in [`artifacts/mirror`](artifacts/mirror) and add it to `artifacts/`. You will also need to manually terminate the servers in the AWS EC2 console, since servers may have been started but their instance IDs have not been saved to the configuration file.

2. When running `start_cluster.py`, if you see a message that a SSH connection was refused on port 22, then the script was not able to copy over the configuration file because the instance had not fully started yet. In this case, either teardown the cluster using `python3 teardown_cluster.py` and restart (waiting a few minutes between teardown and starting again), or manually copy the configuration files yourself using `scp`.

3. When running `start_cluster.py`, if you see that `unzip` command works because it's not a valid `.zip` file, then that means likely the machine you are running `start_cluster.py` on is getting blocked by CloudFlare when trying to pull from the repo. Try to run `start_cluster.py` on a local laptop or desktop instead of a EC2 machine.

4. When running `collect_floss_bench_results.py` after waiting 24 hours, it is possible that your temporary AWS credentials have timed out. This results in either a connection or permission blocked error. In that case, generate fresh AWS temporary credentials, and re-run `aws configure` to add your new credentials.

---

<h2 id="option-2">[Option 2] Step-by-step artifact evaluation walkthrough for users running large experiments without AWS</h2>

Users without AWS access can still run the large experiments if they have local resources comparable to the AWS setup used by the artifact. The AWS setup uses two `c5.18xlarge` instances, each with 72 vCPUs, 144 GB of memory, and up to 25 Gbps networking.

There are two natural local setups:

1. Use two local Ubuntu servers. Each server should have approximately 72 hardware threads, 144 GB of available memory, and a high-bandwidth network connection to the other server. Install the artifact on both servers, create the same `parties.txt` file on both servers, and run the party-0 and party-1 benchmark commands simultaneously.

2. Use one large local Ubuntu server with Docker. Start two Docker containers, allocate 72 threads and 144 GB of memory to each container, and connect them through a Docker network. The network can optionally be shaped to 25 Gbps with Linux traffic control (`tc`) to better match the AWS setting.

The following commands describe the Docker setup used by one reviewer. They assume a local server with at least 144 hardware threads and enough memory to allocate 144 GB to each container. Run the commands from the project root directory after downloading and unpacking the artifact.

### Part 1: Docker Container Setup

1. Build the Docker image. This clones the FLOSS repository inside Docker, installs dependencies, compiles MP-SPDZ, installs OPM dependencies, and builds FLOSS inside the image.

```sh
cd /path/to/floss
docker build --memory=8g \
  --memory-swap=10g \
  -t floss-large-local \
  -f artifacts/local-large.Dockerfile .
```

2. Create a Docker network for the two parties:

```sh
docker network create --driver bridge --subnet 172.28.0.0/16 floss-bench-net
```

3. Start two containers from the image. Adjust the CPU ranges and/or memory if your server has less CPUs and memory available.

```sh
docker run -dit --name floss-party0 \
  --cpuset-cpus="0-71" \
  --memory="144g" \
  --shm-size="16g" \
  --cap-add=NET_ADMIN \
  --privileged=true \
  --network floss-bench-net \
  --ip 172.28.0.2 \
  floss-large-local bash

docker run -dit --name floss-party1 \
  --cpuset-cpus="72-143" \
  --memory="144g" \
  --shm-size="16g" \
  --cap-add=NET_ADMIN \
  --privileged=true \
  --network floss-bench-net \
  --ip 172.28.0.3 \
  floss-large-local bash
```

4. Shape the container network bandwidth to 25 Gbps to match the evaluation network bandwidth:

```sh
docker exec floss-party0 bash -lc "tc qdisc replace dev eth0 root tbf rate 25gbit burst 32mb latency 50ms"
docker exec floss-party1 bash -lc "tc qdisc replace dev eth0 root tbf rate 25gbit burst 32mb latency 50ms"
```

5. Create `parties.txt` inside both containers:

```sh
docker exec floss-party0 bash -lc "cd /root/repo && printf '172.28.0.2:8644\n172.28.0.3:8645\n' > parties.txt"
docker exec floss-party1 bash -lc "cd /root/repo && printf '172.28.0.2:8644\n172.28.0.3:8645\n' > parties.txt"
```

### Part 2: Running and Retrieving Experiments

The following commands should be started in both containers at approximately the same time. Open one terminal for party 0 and one terminal for party 1. If any of the tests fails. just re

On party 0:
1. Run the docker container for party 0
```sh
docker exec -it floss-party0 bash
cd /root/repo
```

2. Run the all of the experiments (if they fail mid-way, run any individual experiment in isolation)
```sh
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench simple_perm_network_shuffle
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench perm_network_shuffle
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench floss_shuffle
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench sort_with_simple_perm_network
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench sort_with_floss
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench sort_with_perm_network
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench sort_with_quicksort
env ALONE=false RANK=0 IP_FILE="parties.txt" cargo bench --bench sort_with_sorting_network
./scripts/bench_opmcc.sh 0 0 172.28.0.2:39530,172.28.0.3:39531
```

3. Exit the container:
```sh
exit
```

On party 1:
1. Run the Docker container for party 1
```sh
docker exec -it floss-party1 bash
cd /root/repo
```

2. Run the all of the experiments (if they fail mid-way, run any individual experiment in isolation)
```sh
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench simple_perm_network_shuffle
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench perm_network_shuffle
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench floss_shuffle
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench sort_with_simple_perm_network
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench sort_with_floss
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench sort_with_perm_network
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench sort_with_quicksort
env ALONE=false RANK=1 IP_FILE="parties.txt" cargo bench --bench sort_with_sorting_network
./scripts/bench_opmcc.sh 0 1 172.28.0.2:39530,172.28.0.3:39531
```

3. Exit the container:
```sh
exit
```

The output CSVs are written to the project root inside each container. As in the AWS setup, collect the CSVs from party 0:

```sh
docker exec floss-party0 bash -lc "mkdir -p /root/results && cp /root/repo/*.csv /root/results/"
docker cp floss-party0:/root/results/. .
```

### Part 3: Creating the Plots

Run scripts to create table results and plots. This can be done on the host after installing the plotting dependencies from [Option 1](#option-1), or inside the party-0 container before copying out the plots.

```sh
cd plots/
python3 gen_plot_data.py
pdflatex main.tex
cd .. # return to project root directory
```

The resulting tables and plots can be viewed using the same commands as in [Option 1](#option-1).

---

<h2 id="option-3">[Option 3] Step-by-step artifact evaluation walkthrough for users running a local computer</h2>

We provide an option for users who want to generate the artifacts on their own local computer. There are certain restrictions. The user must be running either Mac OS X or Ubuntu and have at least 16GB of RAM. We restrict benchmarking to smaller input sizes since we assume that the device does not have memory equivalent to two `c5.18xlarge` instances.

Because of this, users cannot reproduce the pareto plots on a local computer since it requires completing benchmarks with the largest shuffle size `2^20` and sorting size `2^13`. If reproducing pareto plots are desired, users will need to opt for [Option 1](#option-1) or [Option 2](#option-2).

### Part 1: Local Computer Setup

1. [30 minutes] Prerequisite installation and setup.

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

Compile MP-SPDZ and required protocols:

```zsh
cd mp-spdz-0.4.2
echo "MY_CFLAGS += -DINSECURE -Wno-error=unused-parameter" >> CONFIG.mine
make clean
make setup
make -j8 pairwise-offline.x mascot-offline.x lowgear-party.x mascot-party.x
```

The `-DINSECURE` flag enables MP-SPDZ's insecure benchmarking functionality for local key generation. This is intended only for reproducing the artifact benchmarks. The `-Wno-error=unused-parameter` flag prevents MP-SPDZ's vendored `sse2neon` header warnings from stopping the build under `-Werror`. If MP-SPDZ reports `You are trying to use insecure benchmarking functionality for local key generation`, make sure these flags have been added before compilation and rerun `make clean` before rebuilding.

### Part 2: Running and Retrieving Experiments

The provided commands will run the benchmarks synchronously all at once. This means the terminal tab and your computer must remain on at all times during benchmarks, since the benchmarks halt once the computer sleeps.

1. [10 minutes] Run OPM benchmarks on Docker:

```sh
cd OPM/
docker build -t mosac:latest .
docker run -it --name mosac-dev --cap-add=NET_ADMIN --privileged=true mosac:latest bash

./scripts/bench_opmcc.sh 1

exit # exit Docker instance when finished
```

2. [<1 minute] Copy OPM benchmark CSVs from Docker to local directory:

```sh
cd .. # return to project root directory
docker cp mosac-dev:/opm/shuffle_opmcc_offline.csv .
docker cp mosac-dev:/opm/shuffle_opmcc_online.csv .
```

3. [2 hours] Run the remaining baseline benchmarks in ALONE mode:

```sh
cargo bench --bench simple_perm_network_shuffle
cargo bench --bench perm_network_shuffle
cargo bench --bench floss_shuffle
cargo bench --bench sort_with_simple_perm_network
cargo bench --bench sort_with_floss
cargo bench --bench sort_with_perm_network
cargo bench --bench sort_with_quicksort
cargo bench --bench sort_with_sorting_network
```

### Part 3: Creating the Plots

4. Run scripts in ALONE mode to create plots:

```zsh
cd plots/
python3 gen_plot_data.py --alone 1
pdflatex main.tex
cd .. # return to project root directory
```

5. To view plot/table results:

**(Experiment E1) Table 1 + Individual
shuffling data**

```sh
cat plots/plot_data/shuffle_offline_time.csv
cat plots/plot_data/shuffle_online_time.csv
```

**(Experiment E2) Individual
sorting data**

```sh
cat plots/plot_data/sort_offline_time.csv
cat plots/plot_data/sort_online_time.csv
```

**(Experiment E1 + E2) Figures 7-10**

```sh
open plots/main.pdf
```

**(Experiment E1) Table 3 (in Project Root directory)**

```sh
cat shuffle_floss_offline.csv
cat shuffle_perm_network_offline.csv
```
