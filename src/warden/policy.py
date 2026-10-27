"""Load the governance policy. Thresholds live in YAML so they can change without a code change."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import SEVERITIES

DEFAULTS = {
    "dormant_days": 90,
    "never_used_grace_days": 30,
    "password_max_age_days": 365,
    "privileged_groups": [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
    ],
    "weak_kerberos_encryption": ["RC4", "DES"],
    "naming_pattern": r"^svc-[a-z0-9]+(-[a-z0-9]+)*$",
    "severity_weights": {"low": 1, "medium": 3, "high": 8, "critical": 15},
    "priority_thresholds": {"P1": 20, "P2": 8, "P3": 4},
}


@dataclass(frozen=True)
class Policy:
    dormant_days: int
    never_used_grace_days: int
    password_max_age_days: int
    privileged_groups: tuple[str, ...]
    weak_kerberos_encryption: tuple[str, ...]
    naming_pattern: str
    severity_weights: dict
    priority_thresholds: dict

    def is_privileged(self, group: str) -> bool:
        return group.lower() in {g.lower() for g in self.privileged_groups}


def build_policy(overrides: dict | None = None) -> Policy:
    data = overrides or {}
    unknown = set(data) - set(DEFAULTS)
    if unknown:
        # Fail loudly: a typo like "dormat_days" would otherwise silently fall back to the default.
        raise ValueError(f"Unknown policy keys: {', '.join(sorted(unknown))}")
    merged = {**DEFAULTS, **data}

    for key in ("dormant_days", "never_used_grace_days", "password_max_age_days"):
        if not isinstance(merged[key], int) or merged[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    try:
        re.compile(merged["naming_pattern"])
    except re.error as exc:
        raise ValueError(f"naming_pattern is not a valid regex: {exc}") from exc
    missing = set(SEVERITIES) - set(merged["severity_weights"])
    if missing:
        raise ValueError(f"severity_weights missing: {', '.join(sorted(missing))}")
    if set(merged["priority_thresholds"]) != {"P1", "P2", "P3"}:
        raise ValueError("priority_thresholds must define exactly P1, P2 and P3")

    return Policy(
        dormant_days=merged["dormant_days"],
        never_used_grace_days=merged["never_used_grace_days"],
        password_max_age_days=merged["password_max_age_days"],
        privileged_groups=tuple(merged["privileged_groups"]),
        weak_kerberos_encryption=tuple(e.upper() for e in merged["weak_kerberos_encryption"]),
        naming_pattern=merged["naming_pattern"],
        severity_weights=dict(merged["severity_weights"]),
        priority_thresholds=dict(merged["priority_thresholds"]),
    )


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return build_policy()
    with Path(path).open(encoding="utf-8") as handle:
        return build_policy(yaml.safe_load(handle) or {})
