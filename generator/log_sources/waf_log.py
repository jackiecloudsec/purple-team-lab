"""AWS WAF log generators."""

import random
from datetime import datetime

BENIGN_URIS = [
    "/api/v1/health", "/api/v1/users", "/api/v1/products", "/login",
    "/dashboard", "/static/app.js", "/static/style.css", "/favicon.ico",
    "/api/v1/orders", "/api/v1/search?q=shoes",
]

ATTACK_URIS = [
    "/api/v1/users?id=1' OR '1'='1", "/api/v1/search?q=<script>alert(1)</script>",
    "/../../../etc/passwd", "/api/v1/admin' UNION SELECT * FROM users--",
    "/wp-admin/install.php", "/api/v1/debug/vars", "/.env",
    "/api/v1/graphql?query={__schema{types{name}}}",
    "/actuator/env", "/server-status",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "python-requests/2.31.0", "curl/8.4.0", "sqlmap/1.7",
    "Nikto/2.5.0", "DirBuster-1.0-RC1",
]

BENIGN_IPS = ["10.0.1.15", "10.0.1.42", "10.0.2.8", "172.16.0.5"]


def benign_request(ts: datetime) -> dict:
    return {
        "timestamp": int(ts.timestamp() * 1000),
        "formatVersion": 1,
        "webaclId": "arn:aws:wafv2::123456789012:regional/webacl/purple-lab/abc123",
        "action": "ALLOW",
        "httpRequest": {
            "clientIp": random.choice(BENIGN_IPS),
            "country": "US",
            "uri": random.choice(BENIGN_URIS),
            "httpMethod": random.choice(["GET", "POST"]),
            "httpVersion": "HTTP/2.0",
            "headers": [{"name": "User-Agent", "value": random.choice(USER_AGENTS[:2])}],
        },
        "ruleGroupList": [],
        "terminatingRuleId": "Default_Action",
        "terminatingRuleType": "REGULAR",
        "lab_is_attacker": False,
    }


def attack_request(ts: datetime, attacker_ip: str) -> dict:
    uri = random.choice(ATTACK_URIS)
    # Determine which rule would fire
    if "'" in uri or "UNION" in uri or "--" in uri:
        rule = "SQLi_Detection"
        rule_type = "MANAGED_RULE_GROUP"
    elif "<script>" in uri:
        rule = "XSS_Detection"
        rule_type = "MANAGED_RULE_GROUP"
    elif ".." in uri or ".env" in uri or "etc/passwd" in uri:
        rule = "PathTraversal_Detection"
        rule_type = "MANAGED_RULE_GROUP"
    else:
        rule = "SuspiciousEndpoint_Detection"
        rule_type = "REGULAR"

    action = random.choice(["BLOCK", "BLOCK", "BLOCK", "COUNT"])

    return {
        "timestamp": int(ts.timestamp() * 1000),
        "formatVersion": 1,
        "webaclId": "arn:aws:wafv2::123456789012:regional/webacl/purple-lab/abc123",
        "action": action,
        "httpRequest": {
            "clientIp": attacker_ip,
            "country": random.choice(["RU", "CN", "IR", "KP"]),
            "uri": uri,
            "httpMethod": random.choice(["GET", "POST", "PUT"]),
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "User-Agent", "value": random.choice(USER_AGENTS[2:])}],
        },
        "ruleGroupList": [{"ruleGroupId": rule}],
        "terminatingRuleId": rule,
        "terminatingRuleType": rule_type,
        "lab_is_attacker": True,
    }
