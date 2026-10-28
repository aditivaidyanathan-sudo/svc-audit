"""Risk exceptions: approved, time-limited acceptance of a specific finding.

An exception must name the account, the rule, a reason, an approver and an
expiry date. Anything less is rejected. Expired exceptions raise a new finding
instead of quietly lapsing, and critical findings cannot be waived here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .models import DataQualityIssue, Finding

REQUIRED = ("account", "rule", "reason", "approved_by", "expires")


@dataclass
class RiskException:
    account: str
    rule: str
    reason: str
    approved_by: str
    expires: date

    def label(self) -> str:
        return f"{self.account} / {self.rule} (approved by {self.approved_by}, expires {self.expires})"


@dataclass
class ExceptionOutcome:
    applied: list[RiskException] = field(default_factory=list)
    expired: list[RiskException] = field(default_factory=list)
    unused: list[RiskException] = field(default_factory=list)  # no matching account or finding
    refused: list[RiskException] = field(default_factory=list)  # tried to waive a critical finding


def load_exceptions(path: str | Path | None) -> tuple[list[RiskException], list[DataQualityIssue]]:
    if path is None or not Path(path).exists():
        return [], []
    source = Path(path).name
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or []
    if not isinstance(data, list):
        raise ValueError(f"{source} must be a YAML list of exceptions")

    exceptions: list[RiskException] = []
    issues: list[DataQualityIssue] = []
    for index, entry in enumerate(data, start=1):
        if not isinstance(entry, dict):
            issues.append(DataQualityIssue(source, index, "-", str(entry), "exception is not a mapping; ignored"))
            continue
        missing = [k for k in REQUIRED if not str(entry.get(k) or "").strip()]
        if missing:
            issues.append(
                DataQualityIssue(
                    source, index, ",".join(missing), str(entry.get("account", "")),
                    f"invalid exception ignored; missing {', '.join(missing)}",
                )
            )
            continue
        expires = entry["expires"]
        if not isinstance(expires, date):
            try:
                expires = date.fromisoformat(str(expires))
            except ValueError:
                issues.append(
                    DataQualityIssue(source, index, "expires", str(expires), "invalid expiry date; exception ignored")
                )
                continue
        exceptions.append(
            RiskException(
                account=str(entry["account"]).strip(),
                rule=str(entry["rule"]).strip().upper(),
                reason=str(entry["reason"]).strip(),
                approved_by=str(entry["approved_by"]).strip(),
                expires=expires,
            )
        )
    return exceptions, issues


def apply_exceptions(
    findings: dict[str, list[Finding]], exceptions: list[RiskException], as_of: date
) -> ExceptionOutcome:
    outcome = ExceptionOutcome()
    for exc in exceptions:
        matches = [f for f in findings.get(exc.account, []) if f.rule == exc.rule]
        if not matches:
            outcome.unused.append(exc)
            continue
        if exc.expires < as_of:
            outcome.expired.append(exc)
            findings[exc.account].append(
                Finding(exc.account, "EXCEPTION_EXPIRED", "medium",
                        f"Exception for {exc.rule} expired {exc.expires} (approved by {exc.approved_by})")
            )
            continue
        if any(f.severity == "critical" for f in matches):
            outcome.refused.append(exc)
            continue
        for finding in matches:
            finding.suppressed_by = f"exception approved by {exc.approved_by}, expires {exc.expires}"
        outcome.applied.append(exc)
    return outcome
