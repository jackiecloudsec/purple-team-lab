#!/usr/bin/env python3
"""
Seed historical log data for the Purple Team Lab.

Generates 24 hours of backdated logs across all sources so there's
data to hunt on immediately when Splunk starts, before the live
generator kicks in.
"""

import json
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "generator"))

from log_sources import cloudtrail, vpc_flow, guardduty, dns_query, waf_log

STAGING_DIR = os.environ.get("LOG_STAGING_DIR", "/tmp/purple-team-logs")
HOURS_OF_DATA = 24
EVENTS_PER_HOUR = 100

SCENARIOS = [
    {
        "title": "S3 Data Exfiltration",
        "attacker_ip": "198.51.100.42",
        "attacker_identity": "arn:aws:iam::123456789012:user/compromised-dev",
        "cloudtrail_events": ["ListBuckets", "GetObject", "GetBucketAcl", "PutBucketPolicy", "CopyObject"],
        "tactics": ["Discovery", "Exfiltration", "Collection"],
    },
    {
        "title": "IAM Privilege Escalation",
        "attacker_ip": "203.0.113.77",
        "attacker_identity": "arn:aws:sts::123456789012:assumed-role/dev-role/attacker",
        "cloudtrail_events": ["AssumeRole", "CreateAccessKey", "AttachUserPolicy", "CreateUser", "ListRoles"],
        "tactics": ["Privilege Escalation", "Persistence", "Credential Access"],
    },
    {
        "title": "CloudTrail Tampering",
        "attacker_ip": "198.51.100.201",
        "attacker_identity": "arn:aws:iam::123456789012:root",
        "cloudtrail_events": ["StopLogging", "DeleteTrail", "UpdateTrail", "DescribeTrails"],
        "tactics": ["Defense Evasion", "Discovery"],
    },
]


def write_log(source: str, event: dict, index: int):
    ts = event.get("eventTime") or event.get("timestamp") or event.get("createdAt") or event.get("query_timestamp") or ""
    path = f"{STAGING_DIR}/{source}/seed_{index:06d}.json"
    with open(path, "w") as f:
        json.dump(event, f)


def main():
    for subdir in ["cloudtrail", "vpc_flow", "guardduty", "waf", "dns"]:
        Path(f"{STAGING_DIR}/{subdir}").mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow()
    event_idx = 0
    total_events = 0

    print(f"[*] Seeding {HOURS_OF_DATA} hours of data ({EVENTS_PER_HOUR}/hr)")

    for hour_offset in range(HOURS_OF_DATA, 0, -1):
        base_time = now - timedelta(hours=hour_offset)
        scenario = random.choice(SCENARIOS)

        for _ in range(EVENTS_PER_HOUR):
            ts = base_time + timedelta(seconds=random.randint(0, 3600))
            is_attack = random.random() < 0.3
            source_type = random.choices(
                ["cloudtrail", "vpc_flow", "guardduty", "dns", "waf"],
                weights=[35, 25, 10, 20, 10],
                k=1,
            )[0]

            if is_attack:
                if source_type == "cloudtrail":
                    event = cloudtrail.attack_event(ts, scenario["attacker_ip"], scenario["attacker_identity"], scenario["cloudtrail_events"])
                elif source_type == "vpc_flow":
                    event = vpc_flow.attack_flow(ts, scenario["attacker_ip"])
                elif source_type == "guardduty":
                    event = guardduty.attack_finding(ts, scenario["attacker_ip"], scenario["attacker_identity"], scenario["tactics"])
                elif source_type == "dns":
                    event = dns_query.attack_query(ts, scenario["attacker_ip"])
                else:
                    event = waf_log.attack_request(ts, scenario["attacker_ip"])
            else:
                if source_type == "cloudtrail":
                    event = cloudtrail.benign_event(ts)
                elif source_type == "vpc_flow":
                    event = vpc_flow.benign_flow(ts)
                elif source_type == "guardduty":
                    continue  # No benign GuardDuty findings
                elif source_type == "dns":
                    event = dns_query.benign_query(ts)
                else:
                    event = waf_log.benign_request(ts)

            write_log(source_type, event, event_idx)
            event_idx += 1
            total_events += 1

        if hour_offset % 6 == 0:
            print(f"  Generated hour -{hour_offset}... ({total_events} events so far)")

    print(f"[+] Seeded {total_events} total events across {HOURS_OF_DATA} hours")
    print(f"    Output: {STAGING_DIR}/")


if __name__ == "__main__":
    main()
