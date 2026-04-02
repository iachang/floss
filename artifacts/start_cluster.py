import sys, string, json, time, os, datetime
import subprocess
# from benchClient import generateRemoteCmdStr

filename = "system.config"
devNull = open(os.devnull, "w")

region = "us-west-2"
key_name = "FLOSS"
pem_file = f"{key_name}.pem"
root_size_gib = 256

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


def _load_mirror_urls():
    path = os.path.join(SCRIPT_DIR, "mirror_urls.txt")
    urls = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                urls[k.strip()] = v.strip()
    return urls


link = _load_mirror_urls()["ZIP_URL"]

def key_exists_in_aws():
    result = subprocess.run(
        [
            "aws", "ec2", "describe-key-pairs",
            "--region", region,
            "--key-names", key_name
        ],
        capture_output=True,
        text=True
    )   
    return result.returncode == 0

def create_key():
    print(f"Creating new key pair: {key_name}")

    result = subprocess.run(
        [
            "aws", "ec2", "create-key-pair",
            "--region", region,
            "--key-name", key_name,
            "--key-type", "rsa",
            "--query", "KeyMaterial",
            "--output", "text"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error creating key pair:")
        print(result.stderr)
        sys.exit(1)

    # Expand ~/.ssh safely
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(exist_ok=True)

    pem_path = ssh_dir / f"{key_name}.pem"

    with open(pem_path, "w") as f:
        f.write(result.stdout)

    os.chmod(pem_path, 0o400)

    print(f"Saved private key to {pem_path}")

if key_exists_in_aws():
    print("Local key exists")
else:
    create_key()

def get_default_vpc_id():
    result = subprocess.run(
        [
            "aws", "ec2", "describe-vpcs",
            "--query", "Vpcs[?IsDefault==`true`].VpcId",
            "--output", "text"
        ],
        capture_output=True,
        text=True
    )

    return result.stdout.strip()

print("Starting cluster...")

ubuntu_22_04_ami_id = "ami-055c254ebd87b4dba"
vpc_id = get_default_vpc_id()
sg_name = "Floss"

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    return result.stdout.strip(), None

def get_default_vpc():
    output, err = run_cmd([
        "aws", "ec2", "describe-vpcs",
        "--region", region,
        "--query", "Vpcs[?IsDefault==`true`].VpcId",
        "--output", "text"
    ])
    if not output:
        print("Could not determine default VPC")
        sys.exit(1)
    return output

def get_security_group(vpc_id):
    output, err = run_cmd([
        "aws", "ec2", "describe-security-groups",
        "--region", region,
        "--filters",
        f"Name=group-name,Values={sg_name}",
        f"Name=vpc-id,Values={vpc_id}",
        "--query", "SecurityGroups[0].GroupId",
        "--output", "text"
    ])

    if output and output != "None":
        return output
    return None

def create_security_group(vpc_id):
    output, err = run_cmd([
        "aws", "ec2", "create-security-group",
        "--region", region,
        "--group-name", sg_name,
        "--description", "Open all traffic",
        "--vpc-id", vpc_id,
        "--output", "json"
    ])
    if not output:
        print("Error creating security group:", err)
        sys.exit(1)

    group_id = json.loads(output)["GroupId"]
    print(f"Created security group: {group_id}")
    return group_id

def authorize_ingress(group_id):
    print("Adding inbound rule (All traffic 0.0.0.0/0)...")
    subprocess.run([
        "aws", "ec2", "authorize-security-group-ingress",
        "--region", region,
        "--group-id", group_id,
        "--protocol", "-1",
        "--port", "-1",
        "--cidr", "0.0.0.0/0"
    ], check=True)

# ---------------- Main Flow ----------------

vpc_id = get_default_vpc()
print("Using VPC:", vpc_id)

existing_sg = get_security_group(vpc_id)

if existing_sg:
    print(f"Security group already exists: {existing_sg}, utilizing that security group")
else:
    new_sg = create_security_group(vpc_id)
    authorize_ingress(new_sg)

print("Done.")

f_config = open(PROJECT_ROOT + '/artifacts/' + filename, "r")
sysConfig = json.load(f_config)
f_config.close()



# Create two servers
env = os.environ.copy()
env["AWS_DEFAULT_REGION"] = "us-west-2"

output, err = run_cmd([
        "aws", "ec2", "describe-security-groups",
        "--region", region,
        "--filters",
        f"Name=group-name,Values={sg_name}",
        f"Name=vpc-id,Values={vpc_id}",
        "--query", "SecurityGroups[0].GroupId",
        "--output", "text"
    ])

# coordinator_result = subprocess.run(
#     [
#         "aws", "ec2", "run-instances",
#         "--image-id", ubuntu_22_04_ami_id,
#         "--count", "1",
#         "--instance-type", "t2.xlarge",
#         "--key-name", key_name,
#         "--placement", "AvailabilityZone=us-west-2a",
#         "--security-groups", sg_name,
#         "--block-device-mappings",
#         json.dumps([{
#             "DeviceName": "/dev/sda1",
#             "Ebs": {
#                 "VolumeSize": root_size_gib,
#                 "VolumeType": "gp3",
#                 "DeleteOnTermination": True
#             }
#         }]),
#     ],
#     env=env,
#     check=True,
#     capture_output=True, text=True
# )
# coordinator_out = coordinator_result.stdout
# coordinatorConfig = json.loads(coordinator_out)
# coordinatorID = coordinatorConfig["Instances"][0]["InstanceId"]
# coordinatorIP = coordinatorConfig["Instances"][0]["NetworkInterfaces"][0]["PrivateIpAddress"]
# sysConfig["CoordinatorInstanceId"] = coordinatorID
# sysConfig["CoordinatorPrivateIP"] = coordinatorIP

party_result = subprocess.run(
    [
        "aws", "ec2", "run-instances",
        "--image-id", ubuntu_22_04_ami_id,
        "--count", "2",
        "--instance-type", "c5.18xlarge",
        "--key-name", key_name,
        "--placement", "AvailabilityZone=us-west-2a",
        "--security-groups", sg_name,
        "--block-device-mappings",
        json.dumps([{
            "DeviceName": "/dev/sda1",
            "Ebs": {
                "VolumeSize": root_size_gib,
                "VolumeType": "gp3",
                "DeleteOnTermination": True
            }
        }]),
    ],
    env=env,
    check=True,
    capture_output=True, text=True
)
party_out = party_result.stdout
partyConfig = json.loads(party_out)
partyIDs = [instance["InstanceId"] for instance in partyConfig["Instances"]]
partyIPs = [instance["NetworkInterfaces"][0]["PrivateIpAddress"] for instance in partyConfig["Instances"]]
sysConfig["Party0InstanceId"] = partyIDs[0]
sysConfig["Party1InstanceId"] = partyIDs[1]
sysConfig["Party0PrivateIP"] = partyIPs[0]
sysConfig["Party1PrivateIP"] = partyIPs[1]

# Wait for all instances to be fully started
time.sleep(60)

# Receiver public ip address metadata
# coordinator_public_result = subprocess.run(
#     [
#         "aws", "ec2", "describe-instances",
#         "--region", region,
#         "--instance-ids", coordinatorID
#     ],
#     env=env,
#     check=True,
#     capture_output=True, text=True
# )
# coordinator_public_out = coordinator_public_result.stdout
# coordinator_public_config = json.loads(coordinator_public_out)
# coordinator_public_addr = coordinator_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"]
# sysConfig["CoordinatorPublicIP"] = coordinator_public_addr

party0_public_result = subprocess.run(
    [
        "aws", "ec2", "describe-instances",
        "--region", region,
        "--instance-ids", partyIDs[0]
    ],
    env=env,
    check=True,
    capture_output=True, text=True
)
party0_public_out = party0_public_result.stdout
party0_public_config = json.loads(party0_public_out)
party0_public_addr = party0_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"]
sysConfig["Party0PublicIP"] = party0_public_addr

party1_public_result = subprocess.run(
    [
        "aws", "ec2", "describe-instances",
        "--region", region,
        "--instance-ids", partyIDs[1]
    ],
    env=env,
    check=True,
    capture_output=True, text=True
)
party1_public_out = party1_public_result.stdout
party1_public_config = json.loads(party1_public_out)
party1_public_addr = party1_public_config["Reservations"][0]["Instances"][0]["PublicIpAddress"]
sysConfig["Party1PublicIP"] = party1_public_addr

# send the updated config to coordinator
# subprocess.run(
#     [
#         "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", PROJECT_ROOT + '/artifacts/' + filename, "ubuntu@" + sysConfig["CoordinatorPublicIP"] + ":~/"
#     ],
#     check=True,
# )

with open(PROJECT_ROOT + '/artifacts/' + filename, "w") as f:
    json.dump(sysConfig, f, indent=4)

print(f"Saved cluster configuration to {PROJECT_ROOT + '/artifacts/' + filename}")

subprocess.run(
    [
        "curl", "-L", "-o", "repo.zip", link
    ],
    check=True,
)

# copy from this repo to parties (project root)
subprocess.run(
    [
        "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", "-r", "repo.zip", "ubuntu@" + sysConfig["Party0PublicIP"] + ":~/"
    ],
    check=True,
)
subprocess.run(
    [
        "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", "-r", "repo.zip", "ubuntu@" + sysConfig["Party1PublicIP"] + ":~/"
    ],
    check=True,
)


subprocess.run(
    [
        "ssh", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no",
        "ubuntu@" + sysConfig["Party0PublicIP"],
        f"sudo apt update && sudo apt install -y unzip && unzip -o repo.zip -d repo",
    ],
    check=True,
)
subprocess.run(
    [
        "ssh", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no",
        "ubuntu@" + sysConfig["Party0PublicIP"],
        f"cd ~/repo && printf '%s:8644\\n%s:8645\\n' '{sysConfig['Party0PrivateIP']}' '{sysConfig['Party1PrivateIP']}' > parties.txt",
    ],
    check=True,
)

# Party1: same
subprocess.run(
    [
        "ssh", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no",
        "ubuntu@" + sysConfig["Party1PublicIP"],
        f"sudo apt update && sudo apt install -y unzip && unzip -o repo.zip -d repo",
    ],
    check=True,
)
subprocess.run(
    [
        "ssh", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no",
        "ubuntu@" + sysConfig["Party1PublicIP"],
        f"cd ~/repo && printf '%s:8644\\n%s:8645\\n' '{sysConfig['Party0PrivateIP']}' '{sysConfig['Party1PrivateIP']}' > parties.txt",
    ],
    check=True,
)

# create parties.txt file, and send them to parties
# parties_txt = open(PROJECT_ROOT + "/parties.txt", "w")
# parties_txt.write(f"{sysConfig['Party0PrivateIP']}:8644\n")
# parties_txt.write(f"{sysConfig['Party1PrivateIP']}:8645\n")
# parties_txt.close()

# # copy from this repo to parties (project root)
# subprocess.run(
#     [
#         "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", "-r", PROJECT_ROOT + "/parties.txt", "ubuntu@" + sysConfig["Party0PublicIP"] + ":~/"
#     ],
#     check=True,
# )
# subprocess.run(
#     [
#         "scp", "-i", "~/.ssh/" + pem_file, "-o", "StrictHostKeyChecking=no", "-r", PROJECT_ROOT, "ubuntu@" + sysConfig["Party1PublicIP"] + ":~/"
#     ],
#     check=True,
# )


