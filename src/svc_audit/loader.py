"""Load and validate the account export and HR feed.

Bad rows are recorded as data-quality issues instead of crashing the run:
in a real estate the export is always messy, and the mess is itself a finding.
"""
from __future__ import annotations

import csv
from datetime import date, datetime
from pathlib import Path

from .models import ACCOUNT_FIELDS, HR_FIELDS, DataQualityIssue, Person, ServiceAccount

TRUE_VALUES = {"true", "yes", "y", "1"}
FALSE_VALUES = {"false", "no", "n", "0"}


class Context:
    """Where a value came from, so every issue can be traced to a file, row and field."""

    def __init__(self, source: str, issues: list[DataQualityIssue]):
        self.source = source
        self.issues = issues
        self.row = 0

    def issue(self, field: str, value: str, problem: str, level: str = "error") -> None:
        self.issues.append(DataQualityIssue(self.source, self.row, field, value, problem, level))


def parse_date(raw: str, field: str, ctx: Context) -> date | None:
    value = (raw or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(value, "%d/%m/%Y").date()
    except ValueError:
        ctx.issue(field, value, "unparseable date; treated as unknown")
        return None
    if parsed.day <= 12 and parsed.day != parsed.month:
        ctx.issue(field, value, "ambiguous date; interpreted as DD/MM/YYYY (UK)", "warning")
    return parsed


def parse_bool(raw: str, field: str, ctx: Context, *, if_unreadable: bool) -> bool:
    """Unreadable flags fall back to the riskier value, so problems are over-reported, not hidden."""
    value = (raw or "").strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    ctx.issue(field, raw, f"unreadable boolean; assumed {if_unreadable} (riskier value)")
    return if_unreadable


def parse_email(raw: str, field: str, ctx: Context) -> str | None:
    value = (raw or "").strip().lower()
    if not value:
        return None
    if "@" not in value:
        ctx.issue(field, raw, "not an email address; treated as missing")
        return None
    if value != raw:
        ctx.issue(field, raw, "email normalised (case/whitespace)", "warning")
    return value


def split_list(raw: str) -> list[str]:
    return [item.strip() for item in (raw or "").split(";") if item.strip()]


def _open_rows(path: Path, required: list[str]):
    handle = path.open(newline="", encoding="utf-8-sig")
    reader = csv.DictReader(handle)
    missing = set(required) - set(reader.fieldnames or [])
    if missing:
        handle.close()
        raise ValueError(f"{path.name} is missing required columns: {', '.join(sorted(missing))}")
    return handle, reader


def load_accounts(path: str | Path) -> tuple[list[ServiceAccount], list[DataQualityIssue]]:
    path = Path(path)
    issues: list[DataQualityIssue] = []
    ctx = Context(path.name, issues)
    accounts: list[ServiceAccount] = []
    seen: set[str] = set()

    handle, reader = _open_rows(path, ACCOUNT_FIELDS)
    with handle:
        for line, row in enumerate(reader, start=2):  # line 1 is the header
            ctx.row = line
            name = (row["account_name"] or "").strip()
            if not name:
                ctx.issue("account_name", "", "missing account name; row skipped")
                continue
            if name.lower() in seen:
                ctx.issue("account_name", name, "duplicate account row; kept first occurrence")
                continue
            seen.add(name.lower())

            accounts.append(
                ServiceAccount(
                    name=name,
                    description=(row["description"] or "").strip(),
                    owner_email=parse_email(row["owner_email"], "owner_email", ctx),
                    department=(row["department"] or "").strip() or None,
                    created=parse_date(row["created"], "created", ctx),
                    last_logon=parse_date(row["last_logon"], "last_logon", ctx),
                    pwd_last_set=parse_date(row["pwd_last_set"], "pwd_last_set", ctx),
                    password_never_expires=parse_bool(
                        row["password_never_expires"], "password_never_expires", ctx, if_unreadable=True
                    ),
                    enabled=parse_bool(row["enabled"], "enabled", ctx, if_unreadable=True),
                    groups=split_list(row["groups"]),
                    spns=split_list(row["spns"]),
                    kerberos_encryption=(row["kerberos_encryption"] or "").strip().upper() or None,
                )
            )
    return accounts, issues


def load_people(path: str | Path) -> tuple[dict[str, Person], list[DataQualityIssue]]:
    path = Path(path)
    issues: list[DataQualityIssue] = []
    ctx = Context(path.name, issues)
    people: dict[str, Person] = {}

    handle, reader = _open_rows(path, HR_FIELDS)
    with handle:
        for line, row in enumerate(reader, start=2):
            ctx.row = line
            email = parse_email(row["email"], "email", ctx)
            if not email:
                ctx.issue("email", row["email"] or "", "missing email; row skipped")
                continue
            status = (row["status"] or "").strip().lower()
            if status not in {"active", "leaver"}:
                ctx.issue("status", row["status"] or "", "unknown status; person treated as not active")
            people[email] = Person(
                email=email,
                name=(row["name"] or "").strip(),
                department=(row["department"] or "").strip() or None,
                status=status,
                leave_date=parse_date(row["leave_date"], "leave_date", ctx),
                manager_email=parse_email(row["manager_email"], "manager_email", ctx),
            )
    return people, issues
