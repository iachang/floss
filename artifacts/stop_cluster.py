import sys, string, json, time, os
import subprocess
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
filename = "system.config"

f_config = open(PROJECT_ROOT + '/artifacts/' + filename)
sysConfig = json.load(f_config)

region = "us-west-2"

# subprocess.run(
#     [
#         "aws", "ec2", "stop-instances",
#         "--region", region,
#         "--instance-ids", sysConfig["CoordinatorInstanceId"]
#     ],
#     check=True,
# )

subprocess.run(
    [
        "aws", "ec2", "stop-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party0InstanceId"]
    ],
    check=True,
)

subprocess.run(
    [
        "aws", "ec2", "stop-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party1InstanceId"]
    ],
    check=True,
)

print("Finished cluster stop. Wait around 60 seconds before resuming.")