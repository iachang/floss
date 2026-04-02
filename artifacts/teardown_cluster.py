import sys, string, json, os
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
filename = "system.config"

f_config = open(PROJECT_ROOT + '/artifacts/' + filename)
sysConfig = json.load(f_config)

region = "us-west-2"

subprocess.run(
    [
        "aws", "ec2", "terminate-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party0InstanceId"]
    ],
    check=True,
)

subprocess.run(
    [
        "aws", "ec2", "terminate-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party1InstanceId"]
    ],
    check=True,
)

f_config.close()

print("Finished cluster teardown")
