import sys, string, json, time, os
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
filename = "system.config"

f_config = open(PROJECT_ROOT + '/artifacts/' + filename)
sysConfig = json.load(f_config)
f_config.close()

region = "us-west-2"

# start instances
# subprocess.run(
#     [
#         "aws", "ec2", "start-instances",
#         "--region", region,
#         "--instance-ids", sysConfig["CoordinatorInstanceId"]
#     ],
#     check=True,
# )

subprocess.run(
    [
        "aws", "ec2", "start-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party0InstanceId"]
    ],
    check=True,
)

subprocess.run(
    [
        "aws", "ec2", "start-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party1InstanceId"]
    ],
    check=True,
)


# Wait for all instances to be fully started
print("Waiting for cluster to resume before updating public ip")
time.sleep(60)

# update the public ip addresses

# update coordinator server
# coordinator_public_result = subprocess.run(
#     [
#         "aws", "ec2", "describe-instances",
#         "--region", region,
#         "--instance-ids", sysConfig["CoordinatorInstanceId"]
#     ],
#     check=True,
#     capture_output=True, text=True
# )
# coordinator_public_out = coordinator_public_result.stdout
# coordinator_public_config = json.loads(coordinator_public_out)
# newCoordinatorPublicAddr = (coordinator_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"])

# update party 0 server
party0_public_result = subprocess.run(
    [
        "aws", "ec2", "describe-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party0InstanceId"]
    ],
    check=True,
    capture_output=True, text=True
)
party0_public_out = party0_public_result.stdout
party0_public_config = json.loads(party0_public_out)
newParty0PublicAddr = (party0_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"])

# update party 1 server
party1_public_result = subprocess.run(
    [
        "aws", "ec2", "describe-instances",
        "--region", region,
        "--instance-ids", sysConfig["Party1InstanceId"]
    ],
    check=True,
    capture_output=True, text=True
)
party1_public_out = party1_public_result.stdout
party1_public_config = json.loads(party1_public_out)
newParty1PublicAddr = (party1_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"])

f_config = open(PROJECT_ROOT + '/artifacts/' + filename, "w")

# sysConfig["CoordinatorPublicIP"] = newCoordinatorPublicAddr
sysConfig["Party0PublicIP"] = newParty0PublicAddr
sysConfig["Party1PublicIP"] = newParty1PublicAddr

sysConfigBlob = json.dumps(sysConfig)
f_config.write(sysConfigBlob)
f_config.close()

# send the updated config to coordinator
# subprocess.run(
#     [
#         "scp", "-i", "~/.ssh/FLOSS.pem", "-o", "StrictHostKeyChecking=no", filename, "ubuntu@" + sysConfig["CoordinatorPublicIP"] + ":~/"
#     ],
#     check=True,
# )

print("Finished cluster resume")