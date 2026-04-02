import sys, string, json
import subprocess
import os
import threading
import time
import tempfile

username = "ubuntu"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
f_config = open(PROJECT_ROOT + '/artifacts/system.config')
config = json.load(f_config)
f_config.close()
keyPath = "~/.ssh/FLOSS.pem"

def generateRemoteCmdStr(machine, remoteCmd):
    return ("ssh -i %s -o StrictHostKeyChecking=no %s@%s \"%s\"") % (keyPath, username, machine, remoteCmd) 

for rank in range(2):
    cmd = generateRemoteCmdStr(config[f"Party{rank}PublicIP"], "cd ~/repo/ && chmod +x ./artifacts/prereq-install.sh && chmod +x ./scripts/setup-opmcc-bench.sh && chmod +x ./scripts/bench_opmcc.sh && ./artifacts/prereq-install.sh")
    subprocess.run(cmd, shell=True, check=True)

for rank in range(2):
    cmd = generateRemoteCmdStr(config[f"Party{rank}PublicIP"], f"""cd ~/repo/ && setsid nohup bash -lc '
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench simple_perm_network_shuffle > output_simple_network.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench perm_network_shuffle > output_perm.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench floss_shuffle > output_floss.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench sort_with_simple_perm_network > output_sort_with_simple_network.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench sort_with_floss > output_sort_floss.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench sort_with_perm_network > output_sort_perm.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench sort_with_quicksort > output_sort_quick.log 2>&1 ;
env ALONE=false RANK={rank} IP_FILE="parties.txt" cargo bench --bench sort_with_sorting_network > output_sort_net.log 2>&1 ;
./scripts/bench_opmcc.sh {rank} {config["Party0PrivateIP"]}:39530,{config["Party1PrivateIP"]}:39531  > output_opmcc.log 2>&1 ;
' </dev/null >/dev/null 2>&1 &
""")
    subprocess.Popen(cmd, shell=True)


# nohup bash -c '
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_simple_perm_network_shuffle -- --nocapture > output_simple_network.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_perm_network_shuffle -- --nocapture > output_perm.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_floss_shuffle -- --nocapture > output_floss.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_sort_with_simple_perm_network -- --nocapture > output_sort_with_simple_network.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_sort_with_floss -- --nocapture > output_sort_floss.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_sort_with_perm_network -- --nocapture > output_sort_perm.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_sort_with_quicksort -- --nocapture > output_sort_quick.log 2>&1 ;
# env ALONE=false RANK=0 IP_FILE="parties.txt" cargo test --release bench_sort_with_sorting_network -- --nocapture > output_sort_net.log 2>&1 ;
# ./scripts/bench_opmcc.sh 0 172.31.45.170:39530,172.31.45.255:39531
# ' & disown