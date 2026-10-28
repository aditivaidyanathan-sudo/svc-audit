"""Core data types shared across the tool."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

ACCOUNT_FIELDS = [
    "account_name",
    "description",
    "owner_email",
    "department",
    "created",
    "last_logon",
    "pwd_last_set",
    "password_never_expires",
    "enabled",
    "groups",
    "spns",
    "kerberos_encryption",
]

HR_FIELDS = ["email", "name", "department", "status", "leave_date", "manager_email"]

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class ServiceAccount:
    name: str
    description: str = ""
    owner_email: str | None = None
    department: str | None = None
    created: date | None = None
    last_logon: date | None = None
    pwd_last_set: date | None = None
    password_never_expires: bool = False
    enabled: bool = True
    groups: list[str] = field(default_factory=list)
    spns: list[str] = field(default_factory=list)
    kerberos_encryption: str | None = None


@dataclass
class Person:
    email: str
    name: str
    department: str | None = None
    status: str = "active"
    leave_date: date | None = None
    manager_email: str | None = None

    @property
    def is_active(self) -> bool:
        return self.status == "active"


@dataclass
class DataQualityIssue:
    source: str
    row: int
    field: str
    value: str
    problem: str
    level: str = "error"  # "error" = value unusable, "warning" = value used but interpreted


@dataclass
class Finding:
    account: str
    rule: str
    severity: str
    detail: str
    suppressed_by: str | None = None

    @property
    def active(self) -> bool:
        return self.suppressed_by is None
