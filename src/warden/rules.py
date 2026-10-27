"""Governance rules. Each finding names the rule, a severity and a plain-English reason."""
from __future__ import annotations

import re
from datetime import date

from .models import Finding, Person, ServiceAccount
from .policy import Policy

OWNERSHIP_RULES = ("NO_OWNER", "OWNER_LEFT", "OWNER_UNKNOWN")

# Problems that turn a privileged account from "needs review" into "critical".
UNGOVERNED_SIGNALS = OWNERSHIP_RULES + ("DORMANT", "NEVER_USED", "WEAK_KERBEROS", "PWD_STALE")


def evaluate_account(
    account: ServiceAccount, people: dict[str, Person], policy: Policy, as_of: date
) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, severity: str, detail: str) -> None:
        findings.append(Finding(account.name, rule, severity, detail))

    # Ownership: who do we ask about this account?
    owner = people.get(account.owner_email) if account.owner_email else None
    if not account.owner_email:
        add("NO_OWNER", "high", "No owner recorded")
    elif owner is None:
        add("OWNER_UNKNOWN", "medium", f"Owner {account.owner_email} not found in HR feed")
    elif not owner.is_active:
        left = owner.leave_date.isoformat() if owner.leave_date else "unknown date"
        add("OWNER_LEFT", "high", f"Owner {owner.name or owner.email} is not active (left {left})")

    # Access: what can it do?
    privileged = [g for g in account.groups if policy.is_privileged(g)]
    if privileged:
        add("PRIVILEGED", "high", f"Member of privileged group(s): {', '.join(privileged)}")

    # Hygiene: can anyone tell what it is for?
    if not re.fullmatch(policy.naming_pattern, account.name):
        add("NAMING", "low", "Name does not follow the service-account naming convention")
    if not account.description:
        add("NO_DESCRIPTION", "low", "No description; purpose unknown")
    TEMP_WORDS = ("temp", "temporary", "migration")
    if account.enabled and account.created and any(word in account.description.lower() for word in TEMP_WORDS):
        age = (as_of - account.created).days
        if age > policy.temp_account_max_days:
            add("TEMP_ACCOUNT", "medium", f"Described as temporary but {age} days old")
            
    # Usage and credentials only matter while the account can still log on.
    if account.enabled:
        if account.last_logon is None:
            if account.created is None:
                add("NEVER_USED", "medium", "No logon recorded and creation date unknown")
            else:
                age = (as_of - account.created).days
                if age > policy.never_used_grace_days:
                    add("NEVER_USED", "medium", f"Enabled for {age} days with no recorded logon")
        else:
            idle = (as_of - account.last_logon).days
            if idle > policy.dormant_days:
                add("DORMANT", "medium", f"No logon for {idle} days (threshold {policy.dormant_days})")

        if account.password_never_expires:
            add("PWD_NEVER_EXPIRES", "low", "Password set to never expire; rotation depends on manual process")
        if account.pwd_last_set is None:
            add("PWD_STALE", "medium", "Password last-set date unknown")
        else:
            pwd_age = (as_of - account.pwd_last_set).days
            if pwd_age > policy.password_max_age_days:
                add("PWD_STALE", "medium", f"Password is {pwd_age} days old (max {policy.password_max_age_days})")

        if account.spns:
            enc = account.kerberos_encryption
            if enc is None:
                add("WEAK_KERBEROS", "medium", "Has SPN(s) but Kerberos encryption type is not recorded; verify")
            elif enc in policy.weak_kerberos_encryption:
                add(
                    "WEAK_KERBEROS",
                    "high",
                    f"Has SPN(s) and allows {enc}; service tickets can be cracked offline (Kerberoasting)",
                )

    # Combination rule: privileged access plus any governance gap is the highest-risk case.
    if privileged and account.enabled:
        present = {f.rule for f in findings}
        reasons = [r for r in UNGOVERNED_SIGNALS if r in present]
        if reasons:
            add("PRIVILEGED_UNGOVERNED", "critical", f"Privileged account with: {', '.join(reasons)}")

    return findings


def evaluate_all(
    accounts: list[ServiceAccount], people: dict[str, Person], policy: Policy, as_of: date
) -> dict[str, list[Finding]]:
    return {a.name: evaluate_account(a, people, policy, as_of) for a in accounts}


def has_ownership_gap(findings: list[Finding]) -> bool:
    return any(f.rule in OWNERSHIP_RULES and f.active for f in findings)

def test_old_temp_account_is_flagged(people, policy):
    account = make_account(description="temp account for migration", created=days_ago(200))
    assert "TEMP_ACCOUNT" in rules_for(account, people, policy)

def test_new_temp_account_is_not_flagged(people, policy):
    account = make_account(description="temp account for migration", created=days_ago(10))
    assert "TEMP_ACCOUNT" not in rules_for(account, people, policy)
