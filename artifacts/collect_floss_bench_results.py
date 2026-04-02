import sys, string, json
import subprocess
import os
import threading
import time
import tempfile

# Project root: parent of the directory containing this script (artifacts/)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

f_config = open(PROJECT_ROOT + '/artifacts/system.config')
sysConfig = json.load(f_config)
f_config.close()

pem_file = "FLOSS.pem"

subprocess.run(
    [
        "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", "-r",
        "ubuntu@" + sysConfig["Party0PublicIP"] + ":~/repo/*.csv",  # remote source
        str(PROJECT_ROOT),  # copy into project root
    ],
    check=True,
)