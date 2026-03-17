"""
Purple Team Lab — Multi-Source Log Generator

Generates realistic CloudTrail, VPC Flow, GuardDuty, WAF, and DNS logs.
Reads attack patterns from dac_modules (if mounted) to create threat-specific
traffic, then mixes in benign background noise.

Logs are written to the staging directory where Fluent Bit picks them up
and forwards to Splunk via HEC.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from log_sources import cloudtrail, vpc_flow, guardduty, dns_query, waf_log
from scenarios import load_attack_scenarios

STAGING_DIR = os.environ.get("LOG_STAGING_DIR", "/var/log/purple-team")
BATCH_INTERVAL = int(os.environ.get("BATCH_INTERVAL_SECONDS", "30"))
EVENTS_PER_BATCH = int(os.environ.get("EVENTS_PER_BATCH", "50"))
ATTACK_RATIO = float(os.environ.get("ATTACK_RATIO", "0.3"))
DAC_MODULES_PATH = os.environ.get("DAC_MODULES_PATH", "/opt/dac_modules")


def ensure_dirs():
    for subdir in ["cloudtrail", "vpc_flow", "guardduty", "falco", "waf", "dns"]:
        Path(f"{STAGING_DIR}/{subdir}").mkdir(parents=True, exist_ok=True)


def write_log(source: str, event: dict):
    """Write a single log event to the staging directory as JSON."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    path = f"{STAGING_DIR}/{source}/{ts}_{random.randint(1000,9999)}.json"
    with open(path, "w") as f:
        json.dump(event, f)


def generate_batch(scenarios: list):
    """Generate a mixed batch of benign and attack traffic."""
    now = datetime.utcnow()
    attack_count = int(EVENTS_PER_BATCH * ATTACK_RATIO)
    benign_count = EVENTS_PER_BATCH - attack_count

    # Pick a random active scenario for this batch
    scenario = random.choice(scenarios) if scenarios else None

    # Attacker context (consistent per batch for realism)
    attacker_ip = scenario["attacker_ip"] if scenario else f"198.51.100.{random.randint(1, 254)}"
    attacker_user = scenario["attacker_identity"] if scenario else "arn:aws:iam::123456789012:user/unknown"
    target_events = scenario["cloudtrail_events"] if scenario else ["DescribeInstances", "GetObject"]
    tactics = scenario["tactics"] if scenario else ["Discovery"]

    events_generated = {"cloudtrail": 0, "vpc_flow": 0, "guardduty": 0, "waf": 0, "dns": 0}

    # --- Benign background traffic ---
    for _ in range(benign_count):
        source_type = random.choices(
            ["cloudtrail", "vpc_flow", "dns", "waf"],
            weights=[40, 30, 20, 10],
            k=1,
        )[0]
        ts = now - timedelta(seconds=random.randint(0, BATCH_INTERVAL))

        if source_type == "cloudtrail":
            event = cloudtrail.benign_event(ts)
        elif source_type == "vpc_flow":
            event = vpc_flow.benign_flow(ts)
        elif source_type == "dns":
            event = dns_query.benign_query(ts)
        else:
            event = waf_log.benign_request(ts)

        write_log(source_type, event)
        events_generated[source_type] += 1

    # --- Attack traffic ---
    for _ in range(attack_count):
        source_type = random.choices(
            ["cloudtrail", "vpc_flow", "guardduty", "dns"],
            weights=[40, 25, 20, 15],
            k=1,
        )[0]
        ts = now - timedelta(seconds=random.randint(0, BATCH_INTERVAL))

        if source_type == "cloudtrail":
            event = cloudtrail.attack_event(ts, attacker_ip, attacker_user, target_events)
        elif source_type == "vpc_flow":
            event = vpc_flow.attack_flow(ts, attacker_ip)
        elif source_type == "guardduty":
            event = guardduty.attack_finding(ts, attacker_ip, attacker_user, tactics)
        else:
            event = dns_query.attack_query(ts, attacker_ip)

        write_log(source_type, event)
        events_generated[source_type] += 1

    return events_generated, scenario


def main():
    print("[*] Purple Team Lab — Log Generator starting")
    ensure_dirs()

    # Load attack scenarios from dac_modules if available
    scenarios = load_attack_scenarios(DAC_MODULES_PATH)
    print(f"[+] Loaded {len(scenarios)} attack scenarios from dac_modules")
    if not scenarios:
        print("[!] No dac_modules found, using built-in scenarios")
        scenarios = builtin_scenarios()

    batch_num = 0
    while True:
        batch_num += 1
        generated, scenario = generate_batch(scenarios)
        total = sum(generated.values())
        scenario_name = scenario["title"][:50] if scenario else "builtin"
        print(
            f"[Batch {batch_num}] Generated {total} events "
            f"(CT={generated['cloudtrail']} VPC={generated['vpc_flow']} "
            f"GD={generated['guardduty']} DNS={generated['dns']} WAF={generated['waf']}) "
            f"| Scenario: {scenario_name}"
        )
        time.sleep(BATCH_INTERVAL)


def builtin_scenarios():
    """Fallback scenarios when dac_modules are not mounted."""
    return [
        {
            "title": "S3 Data Exfiltration via Compromised IAM User",
            "attacker_ip": "198.51.100.42",
            "attacker_identity": "arn:aws:iam::123456789012:user/compromised-dev",
            "cloudtrail_events": ["ListBuckets", "GetObject", "GetBucketAcl", "PutBucketPolicy"],
            "tactics": ["Discovery", "Exfiltration", "Collection"],
        },
        {
            "title": "IAM Privilege Escalation via Role Chaining",
            "attacker_ip": "203.0.113.77",
            "attacker_identity": "arn:aws:sts::123456789012:assumed-role/dev-role/attacker",
            "cloudtrail_events": ["AssumeRole", "CreateAccessKey", "AttachUserPolicy", "CreateUser", "ListRoles"],
            "tactics": ["Privilege Escalation", "Persistence", "Credential Access"],
        },
        {
            "title": "EC2 Instance Compromise and Lateral Movement",
            "attacker_ip": "192.0.2.100",
            "attacker_identity": "arn:aws:iam::123456789012:user/admin",
            "cloudtrail_events": ["DescribeInstances", "RunInstances", "AuthorizeSecurityGroupIngress", "CreateKeyPair"],
            "tactics": ["Initial Access", "Lateral Movement", "Execution"],
        },
        {
            "title": "CloudTrail Tampering and Log Evasion",
            "attacker_ip": "198.51.100.201",
            "attacker_identity": "arn:aws:iam::123456789012:root",
            "cloudtrail_events": ["StopLogging", "DeleteTrail", "UpdateTrail", "DescribeTrails", "PutEventSelectors"],
            "tactics": ["Defense Evasion", "Discovery"],
        },
        {
            "title": "Cryptomining via Unauthorized EC2 Instances",
            "attacker_ip": "203.0.113.200",
            "attacker_identity": "arn:aws:iam::123456789012:user/dev-deploy",
            "cloudtrail_events": ["RunInstances", "DescribeInstanceTypes", "ModifyInstanceAttribute", "CreateSecurityGroup"],
            "tactics": ["Impact", "Execution", "Resource Development"],
        },
    ]


if __name__ == "__main__":
    main()
