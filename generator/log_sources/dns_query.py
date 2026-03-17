"""Route53 DNS query log generators."""

import random
import string
from datetime import datetime

INTERNAL_IPS = ["10.0.1.15", "10.0.1.42", "10.0.2.8", "10.0.2.77", "10.0.3.100"]

BENIGN_DOMAINS = [
    "api.amazonaws.com", "s3.us-east-1.amazonaws.com", "sts.amazonaws.com",
    "ec2.us-east-1.amazonaws.com", "monitoring.us-east-1.amazonaws.com",
    "logs.us-east-1.amazonaws.com", "sqs.us-east-1.amazonaws.com",
    "dynamodb.us-east-1.amazonaws.com", "lambda.us-east-1.amazonaws.com",
    "kms.us-east-1.amazonaws.com", "secretsmanager.us-east-1.amazonaws.com",
    "github.com", "registry.npmjs.org", "pypi.org",
]

SUSPICIOUS_DOMAINS = [
    "c2-server-{rand}.evil.example.com",
    "data-{rand}.exfil.bad-actor.net",
    "{rand}.dga-domain.xyz",
    "update.legit-looking-{rand}.com",
    "api.totally-not-malware-{rand}.io",
]


def _rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def benign_query(ts: datetime) -> dict:
    return {
        "version": "1.100000",
        "account_id": "123456789012",
        "region": "us-east-1",
        "vpc_id": "vpc-0abc123",
        "query_timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query_name": random.choice(BENIGN_DOMAINS),
        "query_type": random.choice(["A", "AAAA", "CNAME"]),
        "query_class": "IN",
        "rcode": "NOERROR",
        "answers": [],
        "srcAddr": random.choice(INTERNAL_IPS),
        "srcPort": str(random.randint(1024, 65535)),
        "transport": "UDP",
        "srcIds": {"instance": f"i-{_rand_str(12)}", "resolver_endpoint": "rslvr-in-0abc123"},
        "lab_is_attacker": False,
    }


def attack_query(ts: datetime, attacker_ip: str) -> dict:
    # Pick between DGA-like long subdomain, TXT exfil, or known-bad domain
    attack_type = random.choice(["dga", "exfil_txt", "c2"])

    if attack_type == "dga":
        domain = f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(30, 60)))}.dga-domain.xyz"
        qtype = "A"
    elif attack_type == "exfil_txt":
        encoded = _rand_str(48)
        domain = f"{encoded}.data.exfil.bad-actor.net"
        qtype = "TXT"
    else:
        template = random.choice(SUSPICIOUS_DOMAINS)
        domain = template.replace("{rand}", _rand_str(6))
        qtype = random.choice(["A", "CNAME"])

    return {
        "version": "1.100000",
        "account_id": "123456789012",
        "region": "us-east-1",
        "vpc_id": "vpc-0abc123",
        "query_timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query_name": domain,
        "query_type": qtype,
        "query_class": "IN",
        "rcode": random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
        "answers": [],
        "srcAddr": attacker_ip,
        "srcPort": str(random.randint(1024, 65535)),
        "transport": "UDP",
        "srcIds": {"instance": f"i-{_rand_str(12)}"},
        "lab_is_attacker": True,
    }
