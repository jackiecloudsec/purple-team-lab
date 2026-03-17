"""
Load attack scenarios from dac_modules.

Each dac_module Python file contains a detection dict with fields like:
  title, severity, tactics, cloudtrail_events, mitre_ttps, etc.

We parse these to build attack scenarios for the log generator.
"""

import importlib.util
import random
from pathlib import Path


ATTACKER_IPS = [
    "198.51.100.42", "203.0.113.77", "192.0.2.100",
    "198.51.100.201", "203.0.113.200", "192.0.2.55",
]

ATTACKER_USERS = [
    "arn:aws:iam::123456789012:user/compromised-dev",
    "arn:aws:sts::123456789012:assumed-role/dev-role/attacker",
    "arn:aws:iam::123456789012:user/admin",
    "arn:aws:iam::123456789012:root",
    "arn:aws:sts::123456789012:assumed-role/LambdaExec/session",
]


def load_attack_scenarios(dac_path: str) -> list:
    """Scan dac_modules directory and extract attack scenarios."""
    scenarios = []
    dac_dir = Path(dac_path)

    if not dac_dir.exists():
        print(f"[!] dac_modules path not found: {dac_path}")
        return scenarios

    for py_file in dac_dir.rglob("*.py"):
        if py_file.name.startswith("__"):
            continue
        try:
            scenario = _parse_dac_module(py_file)
            if scenario:
                scenarios.append(scenario)
        except Exception:
            pass

    return scenarios


def _parse_dac_module(filepath: Path) -> dict | None:
    """Extract scenario data from a dac_module file by importing it."""
    try:
        spec = importlib.util.spec_from_file_location(filepath.stem, filepath)
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        detection = None
        for attr_name in ["DETECTION", "detection", "RULE", "rule"]:
            detection = getattr(mod, attr_name, None)
            if detection and isinstance(detection, dict):
                break

        if not detection:
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if isinstance(obj, dict) and "title" in obj:
                    detection = obj
                    break

        if not detection:
            return None

        ct_events = detection.get("cloudtrail_events", [])
        if not ct_events:
            return None

        return {
            "title": detection.get("title", filepath.stem),
            "severity": detection.get("severity", "medium"),
            "tactics": detection.get("tactics", ["Discovery"]),
            "cloudtrail_events": ct_events,
            "mitre_ttps": detection.get("mitre_ttps", []),
            "attacker_ip": random.choice(ATTACKER_IPS),
            "attacker_identity": random.choice(ATTACKER_USERS),
            "source_file": str(filepath),
        }
    except Exception:
        return None
