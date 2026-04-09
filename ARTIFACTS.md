# FLOSS Artifact Evaluation:

## Reproducing Results

We provide two options for reproducing paper results. The first option is for those with AWS resources, and the second option is for those running on a local computer.

1. [Option 1 [Recommended]](#option-1) produces full benchmark plots for FLOSS (and all other baselines), but requires access to running two AWS `c5.18xlarge` instances continuously for up to 24 hours. It is a simple setup consisting of several one-run scripts.

2. [Option 2](#option-2) produces subsamples of the benchmark plots for FLOSS (and all other baselines) since we assume execution on a single machine with 16GB RAM and Apple M4 chip (or similar processing power). Larger input sizes are omitted to prevent exceeding memory consumption. Therefore, the pareto plots are not reproducible in this setting.

---

<h2 id="option-1">[Option 1] Step-by-step artifact evaluation walkthrough for users with AWS Access</h2>

This is the only way to replicate the full benchmark results of FLOSS. Provided access to AWS credentials, these one-run scripts will launch two `c5.18xlarge` instances and then run the full benchmark suite in whole.

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

**Table 1**

```sh
cat plots/plot_data/shuffle_offline_time.csv
cat plots/plot_data/shuffle_online_time.csv
```

**Table 3 (in Project Root directory)**

```sh
cat shuffle_floss_offline.csv
cat shuffle_perm_network_offline.csv
```

**Figures 7–10**

```sh
open plots/main.pdf
```

### Common issues:

1. When running `start_cluster.py`, if you see a JSONDecodeError involving `json.loads(out)` and `raise JSONDecodeError("Expecting value", s, err.value)`, it means that the `system.config` file is missing or corrupted. In this case, download the latest `system.config` file from the `SYSTEM_CONFIG_URL` entry in [`artifacts/mirror`](artifacts/mirror) and add it to `artifacts/`. You will also need to manually terminate the servers in the AWS EC2 console, since servers may have been started but their instance IDs have not been saved to the configuration file.

2. When running `start_cluster.py`, if you see a message that a SSH connection was refused on port 22, then the script was not able to copy over the configuration file because the instance had not fully started yet. In this case, either teardown the cluster using `python3 teardown_cluster.py` and restart (waiting a few minutes between teardown and starting again), or manually copy the configuration files yourself using `scp`.

3. When running `start_cluster.py`, if you see that `unzip` command works because it's not a valid `.zip` file, then that means likely the machine you are running `start_cluster.py` on is getting blocked by CloudFlare when trying to pull from the repo. Try to run `start_cluster.py` on a local laptop or desktop instead of a EC2 machine.

4. When running `collect_floss_bench_results.py` after waiting 24 hours, it is possible that your temporary AWS credentials have timed out. This results in either a connection or permission blocked error. In that case, generate fresh AWS temporary credentials, and re-run `aws configure` to add your new credentials.

---

<h2 id="option-2">[Option 2] Step-by-step artifact evaluation walkthrough for users running a local computer</h2>

We provide an option for users who want to generate the artifacts on their own local computer. There are certain restrictions. The user must be running either Mac OS X or Ubuntu and have at least 16GB of RAM. We restrict benchmarking to smaller input sizes since we assume that the device does not have memory equivalent to two `c5.18xlarge` instances.

Because of this, users cannot reproduce the pareto plots on a local computer since it requires completing benchmarks with the largest shuffle size `2^20` and sorting size `2^13`. If reproducing pareto plots are desired, users will need to opt for [Option 1](#option-1).

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
make clean
make setup
make -j8 pairwise-offline.x mascot-offline.x lowgear-party.x mascot-party.x
```

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

**Table 1**

```sh
cat plots/plot_data/shuffle_offline_time.csv
cat plots/plot_data/shuffle_online_time.csv
```

**Table 3 (in Project Root directory)**

```sh
cat shuffle_floss_offline.csv
cat shuffle_perm_network_offline.csv
```

**Figures 7 and 9**

```sh
open plots/main.pdf
```
