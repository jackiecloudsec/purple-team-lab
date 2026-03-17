"""VPC Flow Log generators."""

import random
from datetime import datetime

INTERNAL_IPS = ["10.0.1.15", "10.0.1.42", "10.0.2.8", "10.0.2.77", "10.0.3.100"]
EXTERNAL_IPS = ["52.94.133.10", "54.239.28.85", "34.226.14.0", "44.234.90.1"]
ENIS = ["eni-0a1b2c3d4e5f", "eni-1f2e3d4c5b6a", "eni-9z8y7x6w5v4u", "eni-aabb1122ccdd"]
NORMAL_PORTS = [80, 443, 8080, 8443, 5432, 3306]
SUSPICIOUS_PORTS = [22, 3389, 4444, 1337, 6379, 9200, 27017, 8888, 4443]


def benign_flow(ts: datetime) -> dict:
    return {
        "version": 2,
        "account-id": "123456789012",
        "interface-id": random.choice(ENIS),
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "srcAddr": random.choice(INTERNAL_IPS),
        "dstAddr": random.choice(EXTERNAL_IPS + INTERNAL_IPS),
        "srcPort": random.randint(1024, 65535),
        "dstPort": random.choice(NORMAL_PORTS),
        "protocol": 6,
        "packets": random.randint(5, 500),
        "bytes": random.randint(500, 50000),
        "start": int(ts.timestamp()),
        "end": int(ts.timestamp()) + random.randint(1, 60),
        "action": "ACCEPT",
        "log-status": "OK",
        "lab_is_attacker": False,
    }


def attack_flow(ts: datetime, attacker_ip: str) -> dict:
    dst = random.choice(INTERNAL_IPS)
    port = random.choice(SUSPICIOUS_PORTS + NORMAL_PORTS)
    action = "REJECT" if (port in SUSPICIOUS_PORTS and random.random() > 0.4) else "ACCEPT"
    bytes_tx = 0 if action == "REJECT" else random.randint(40, 500000)

    return {
        "version": 2,
        "account-id": "123456789012",
        "interface-id": random.choice(ENIS),
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "srcAddr": attacker_ip,
        "dstAddr": dst,
        "srcPort": random.randint(1024, 65535),
        "dstPort": port,
        "protocol": random.choice([6, 17]),
        "packets": random.randint(1, 200),
        "bytes": bytes_tx,
        "start": int(ts.timestamp()),
        "end": int(ts.timestamp()) + random.randint(1, 120),
        "action": action,
        "log-status": "OK",
        "lab_is_attacker": True,
    }
