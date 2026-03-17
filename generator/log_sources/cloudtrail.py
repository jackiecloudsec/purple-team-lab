"""CloudTrail log event generators."""

import random
from datetime import datetime

BENIGN_EVENTS = [
    "DescribeInstances", "ListBuckets", "GetBucketLocation", "HeadObject",
    "AssumeRole", "GetCallerIdentity", "DescribeSecurityGroups",
    "DescribeSubnets", "DescribeVpcs", "GetObject", "PutObject",
    "ListObjects", "DescribeLoadBalancers", "DescribeAutoScalingGroups",
    "DescribeAlarms", "GetMetricData", "ListFunctions20150331",
    "DescribeDBInstances", "ListUsers", "ListRoles",
]

BENIGN_USERS = [
    "arn:aws:iam::123456789012:user/deploy-svc",
    "arn:aws:iam::123456789012:user/monitoring-bot",
    "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForECS/ecs-task",
    "arn:aws:iam::123456789012:user/ci-pipeline",
    "arn:aws:sts::123456789012:assumed-role/LambdaExec/lambda-fn-abc",
    "arn:aws:iam::123456789012:root",
]

BENIGN_IPS = ["10.0.1.5", "10.0.1.42", "10.0.2.8", "172.16.0.12", "10.0.3.100"]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

AGENTS = [
    "aws-cli/2.15.0 Python/3.11.6",
    "Boto3/1.34.0 Python/3.11.6",
    "console.amazonaws.com",
    "lambda.amazonaws.com",
    "ecs.amazonaws.com",
    "config.amazonaws.com",
]

EVENT_SOURCES = {
    "Describe": "ec2.amazonaws.com", "List": "s3.amazonaws.com",
    "Get": "s3.amazonaws.com", "Put": "s3.amazonaws.com",
    "Create": "ec2.amazonaws.com", "Delete": "ec2.amazonaws.com",
    "Run": "ec2.amazonaws.com", "Start": "ec2.amazonaws.com",
    "Stop": "ec2.amazonaws.com", "Attach": "iam.amazonaws.com",
    "Detach": "iam.amazonaws.com", "Update": "iam.amazonaws.com",
    "Assume": "sts.amazonaws.com", "Authorize": "ec2.amazonaws.com",
    "Revoke": "ec2.amazonaws.com", "Modify": "ec2.amazonaws.com",
    "Head": "s3.amazonaws.com",
}


def _event_source(event_name: str) -> str:
    for prefix, src in EVENT_SOURCES.items():
        if event_name.startswith(prefix):
            return src
    return "cloudtrail.amazonaws.com"


def benign_event(ts: datetime) -> dict:
    event_name = random.choice(BENIGN_EVENTS)
    return {
        "eventVersion": "1.09",
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": event_name,
        "eventSource": _event_source(event_name),
        "sourceIPAddress": random.choice(BENIGN_IPS),
        "userIdentity": {"arn": random.choice(BENIGN_USERS), "type": "IAMUser"},
        "userAgent": random.choice(AGENTS),
        "awsRegion": random.choice(REGIONS),
        "requestParameters": {},
        "responseElements": None,
        "errorCode": None,
        "errorMessage": None,
        "readOnly": event_name.startswith(("Get", "List", "Describe", "Head")),
        "eventCategory": "Management",
        "lab_is_attacker": False,
    }


def attack_event(ts: datetime, attacker_ip: str, attacker_user: str, target_events: list) -> dict:
    event_name = random.choice(target_events) if target_events else random.choice(BENIGN_EVENTS)
    error = None
    error_msg = None
    if random.random() > 0.65:
        error = random.choice(["AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"])
        error_msg = f"User: {attacker_user} is not authorized to perform: {event_name}"

    return {
        "eventVersion": "1.09",
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": event_name,
        "eventSource": _event_source(event_name),
        "sourceIPAddress": attacker_ip,
        "userIdentity": {"arn": attacker_user, "type": "AssumedRole" if "assumed-role" in attacker_user else "IAMUser"},
        "userAgent": random.choice(["aws-cli/2.15.0 Python/3.11.6", "Boto3/1.34.0 Python/3.11.6", "python-requests/2.31.0"]),
        "awsRegion": random.choice(REGIONS),
        "requestParameters": {},
        "responseElements": None,
        "errorCode": error,
        "errorMessage": error_msg,
        "readOnly": event_name.startswith(("Get", "List", "Describe", "Head")),
        "eventCategory": "Management",
        "lab_is_attacker": True,
    }
