"""GuardDuty finding generators."""

import random
from datetime import datetime

FINDING_TYPES = {
    "Reconnaissance": [
        ("Recon:EC2/PortProbeUnprotectedPort", 5.0, "EC2 instance probed on unprotected port"),
        ("Recon:IAMUser/MaliciousIPCaller.Custom", 5.0, "Reconnaissance APIs invoked from malicious IP"),
    ],
    "Initial Access": [
        ("UnauthorizedAccess:IAMUser/MaliciousIPCaller", 8.0, "API invoked from known malicious IP"),
        ("UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", 6.0, "Console login from unusual location"),
    ],
    "Credential Access": [
        ("CredentialAccess:Kubernetes/MaliciousIPCaller", 8.0, "K8s API invoked from malicious IP"),
        ("UnauthorizedAccess:EC2/SSHBruteForce", 6.0, "SSH brute force attack detected"),
    ],
    "Persistence": [
        ("Persistence:IAMUser/AnomalousBehavior", 7.0, "IAM APIs for persistence from unusual principal"),
    ],
    "Discovery": [
        ("Discovery:S3/MaliciousIPCaller", 5.0, "S3 APIs invoked from malicious IP"),
    ],
    "Exfiltration": [
        ("Exfiltration:S3/AnomalousBehavior", 8.5, "Anomalous S3 data access pattern"),
    ],
    "Impact": [
        ("Impact:EC2/BitcoinMining", 9.0, "EC2 communicating with crypto mining IPs"),
    ],
    "Lateral Movement": [
        ("UnauthorizedAccess:EC2/SSHBruteForce", 6.0, "SSH brute force between internal hosts"),
    ],
}

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


def attack_finding(ts: datetime, attacker_ip: str, attacker_user: str, tactics: list) -> dict:
    # Pick a finding type that matches the scenario tactics
    candidates = []
    for tactic in tactics:
        candidates.extend(FINDING_TYPES.get(tactic, []))
    if not candidates:
        candidates = FINDING_TYPES["Reconnaissance"]

    finding_type, severity, description = random.choice(candidates)
    region = random.choice(REGIONS)

    return {
        "schemaVersion": "2.0",
        "accountId": "123456789012",
        "region": region,
        "id": f"pt-{random.randint(100000, 999999)}",
        "type": finding_type,
        "severity": severity,
        "createdAt": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updatedAt": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "title": f"{finding_type.split('/')[1] if '/' in finding_type else finding_type}",
        "description": f"{description}. Actor: {attacker_ip} ({attacker_user}).",
        "service": {
            "serviceName": "guardduty",
            "action": {
                "actionType": "AWS_API_CALL" if "IAM" in finding_type else "NETWORK_CONNECTION",
                "remoteIpDetails": {
                    "ipAddressV4": attacker_ip,
                    "country": {"countryName": random.choice(["Russia", "China", "North Korea", "Iran", "Unknown"])},
                    "organization": {"asn": random.randint(10000, 99999), "asnOrg": "Suspicious-ASN"},
                },
            },
        },
        "resource": {
            "resourceType": "AccessKey" if "IAM" in finding_type else "Instance",
            "accessKeyDetails": {"userName": attacker_user.split("/")[-1] if "/" in attacker_user else attacker_user},
        },
        "lab_is_attacker": True,
    }
