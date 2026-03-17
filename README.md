# Purple Team Lab

Self-contained security operations lab for threat hunting, detection engineering, and purple team exercises. Runs locally via Docker Compose with Splunk Free as the SIEM.

## What It Does

Generates realistic multi-source AWS security logs (CloudTrail, VPC Flow, GuardDuty, WAF, DNS) with a mix of benign traffic and attack scenarios. Attack scenarios are loaded from the [jackiecloudsec-blog](https://github.com/jackiecloudsec/cloud-sec-blog) detection-as-code modules, so every scraped threat automatically becomes a huntable scenario.

**Log sources → Fluent Bit → Splunk**

| Index | Source | What It Contains |
|-------|--------|-----------------|
| `cloudtrail` | AWS CloudTrail | API calls, IAM activity, error codes |
| `vpc_flow` | VPC Flow Logs | Network flows, ACCEPT/REJECT, bytes/packets |
| `guardduty` | GuardDuty | Threat findings with severity scores |
| `waf` | AWS WAF | HTTP requests, SQLi/XSS blocks |
| `dns` | Route53 Query Logs | DNS queries, DGA detection, exfil patterns |
| `falco` | Falco (future) | Container runtime security alerts |

## Quick Start

```bash
git clone https://github.com/jackiecloudsec/purple-team-lab.git
cd purple-team-lab

# Optional: clone the blog repo next to this for real detection scenarios
git clone https://github.com/jackiecloudsec/cloud-sec-blog.git ../csb

# Bootstrap (builds, starts, waits for Splunk)
./scripts/bootstrap.sh

# Seed 24 hours of historical data
python3 scripts/seed_data.py
```

## Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Splunk Web | http://localhost:8000 | admin / PurpleTeam2026! |
| MinIO Console | http://localhost:9001 | purpleadmin / PurpleTeam2026! |

## Architecture

```
┌─────────────────┐     ┌────────────┐     ┌────────────────┐
│  Log Generator   │────▶│  Staging   │────▶│   Fluent Bit   │
│  (Python)        │     │  (Volume)  │     │   (Log Router) │
│                  │     │            │     │                │
│  Reads from:     │     │ cloudtrail/│     │  Parses JSON   │
│  - dac_modules   │     │ vpc_flow/  │     │  Routes by tag │
│  - built-in      │     │ guardduty/ │     │  Sends to HEC  │
│    scenarios     │     │ waf/       │     │                │
│                  │     │ dns/       │     │                │
└─────────────────┘     └────────────┘     └───────┬────────┘
                                                    │
                                                    ▼
                                           ┌────────────────┐
                                           │    Splunk Free  │
┌─────────────────┐                        │                │
│     MinIO        │                        │  6 indexes     │
│  (S3-compatible) │◀── future: direct ──▶ │  10 saved      │
│  Log archive     │    log ingest         │    searches    │
│                  │                        │  HEC on :8088  │
└─────────────────┘                        └────────────────┘
```

## Pre-Built Detection Rules (Saved Searches)

The lab ships with 10 Splunk saved searches that run on schedule:

- **Unauthorized API from Malicious IP** — repeated AccessDenied from single IP
- **VPC Flow Port Scan Detection** — REJECT on 5+ unique ports
- **GuardDuty High Severity Findings** — severity >= 7.0
- **Anomalous API Diversity** — 8+ unique API calls from one IP
- **IAM Persistence Indicators** — CreateUser, CreateAccessKey, AttachPolicy
- **S3 Data Exfiltration Pattern** — cross-correlates CloudTrail S3 API + VPC flow bytes
- **SSH Brute Force via VPC Flow** — 10+ SSH REJECTs from one IP
- **Cross-Source IP Correlation** — IPs appearing in 2+ log sources
- **Lateral Movement Detection** — connections to multiple hosts on RDP/SSH ports
- **DNS Exfiltration Indicator** — long subdomains or TXT query abuse

## Hunting Queries

```spl
# Find attacker IPs across all sources
index=cloudtrail OR index=vpc_flow OR index=guardduty
| eval src=coalesce(sourceIPAddress, srcAddr, actorIp)
| stats dc(index) as sources, count by src
| where sources >= 2

# VPC flow: large transfers from external IPs
index=vpc_flow action="ACCEPT" bytes>100000
| stats sum(bytes) as total_bytes by srcAddr
| sort -total_bytes

# DNS tunneling candidates
index=dns
| eval subdomain_len=len(mvindex(split(query_name, "."), 0))
| where subdomain_len > 30

# Timeline: all attacker activity
index=* lab_is_attacker=true
| sort _time
| table _time index eventName srcAddr dstAddr severity
```

## Connecting to jackiecloudsec-blog

If the `csb/dac_modules` directory exists next to this repo, the generator automatically loads detection scenarios from your scraped threats. When you run the scraper and new detections appear, the lab picks them up on the next batch cycle.

Future integration: the jackiecloudsec-blog sandbox API (`/api/sandbox/{entry_id}`) could query Splunk's REST API directly instead of generating synthetic data.

## Resource Requirements

- **CPU:** 2 cores minimum
- **RAM:** 4GB minimum (Splunk ~2GB, MinIO ~256MB, generator ~128MB)
- **Disk:** 10-20GB for log retention
- **Docker:** 20.10+

## Commands

```bash
# Start the lab
docker compose up -d

# Stop the lab
docker compose down

# View generator output
docker compose logs -f generator

# Rebuild after code changes
docker compose build generator && docker compose up -d generator

# Seed historical data
python3 scripts/seed_data.py

# Clear all data and start fresh
docker compose down -v
./scripts/bootstrap.sh
```

## Roadmap

- [ ] Add Wazuh as second SIEM option
- [ ] Falco runtime alerts from actual containers
- [ ] Caldera integration for automated ATT&CK adversary emulation
- [ ] Live dashboard on jackiecloudsec-blog pulling from Splunk API
- [ ] MinIO event notifications → direct Splunk ingest
- [ ] K3s manifests for Kubernetes deployment
