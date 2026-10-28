"""Generate a deliberately messy, synthetic service-account estate.

Produces three files:
- service_accounts.csv: a directory-style export with realistic problems baked in
- hr_people.csv: an HR feed with joiners, leavers and reporting lines
- exceptions.yaml: a small risk-exception register, including bad entries

Four scripted scenario accounts make the demo tell a story; everything else is random
but reproducible from the seed. All names, emails and domains are fictional.
"""
from __future__ import annotations

import csv
import random
from datetime import date, timedelta
from pathlib import Path

import yaml

from .models import ACCOUNT_FIELDS, HR_FIELDS

DEPARTMENTS = {
    "Trading": ["oms", "fixgateway", "riskcalc", "pricing"],
    "Finance": ["payments", "ledger", "recon", "invoicing"],
    "Data": ["etl", "warehouse", "feeds", "reporting"],
    "Infrastructure": ["backup", "monitoring", "patching", "dns"],
    "Research": ["backtest", "notebooks", "simulation"],
}
ENVIRONMENTS = ["prod", "uat", "dev", "batch", "api", "sched"]
FIRST_NAMES = [
    "Amara", "Ben", "Chloe", "Dev", "Elena", "Femi", "Grace", "Hiro", "Isla", "Jonah",
    "Kavya", "Liam", "Maya", "Nikhil", "Olivia", "Priya", "Quinn", "Rafael", "Sana", "Tom",
    "Uma", "Victor", "Wen", "Xavier", "Yara", "Zain", "Aisha", "Callum", "Freya", "Omar",
]
LAST_NAMES = [
    "Adeyemi", "Brooks", "Chen", "Desai", "Evans", "Fischer", "Gupta", "Hughes", "Ivanova", "Jones",
    "Khan", "Lopez", "Mensah", "Novak", "Okafor", "Patel", "Quinn", "Rossi", "Singh", "Taylor",
    "Usman", "Varga", "Walsh", "Xu", "Yilmaz", "Zhou", "Morgan", "Reid", "Shah", "Byrne",
]
RISKY_GROUPS = ["Domain Admins", "Account Operators", "Server Operators", "Enterprise Admins"]
TRUE_STYLES = ["TRUE", "True", "yes", "1"]
FALSE_STYLES = ["FALSE", "False", "no", "0"]
DOMAIN = "corp.example"


def _people(rng: random.Random, as_of: date, per_department: int) -> list[dict]:
    people, used = [], set()
    for department in DEPARTMENTS:
        head_email = None
        for i in range(per_department):
            while True:
                first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
                if (first, last) not in used:
                    used.add((first, last))
                    break
            email = f"{first}.{last}@{DOMAIN}".lower()
            if i == 0:
                head_email, status, manager = email, "active", None
            else:
                # i == 1 guarantees every department has at least one leaver.
                status = "leaver" if i == 1 or rng.random() < 0.15 else "active"
                manager = head_email
            people.append({
                "email": email,
                "name": f"{first} {last}",
                "department": department,
                "status": status,
                "leave_date": as_of - timedelta(days=rng.randint(10, 700)) if status == "leaver" else None,
                "manager_email": manager,
            })
    return people


def _pick(people: list[dict], department: str, *, status: str, head: bool = False) -> dict:
    matches = [p for p in people if p["department"] == department and p["status"] == status
               and (p["manager_email"] is None) == head]
    return matches[0]


def _scenarios(people: list[dict], as_of: date) -> list[dict]:
    days = lambda n: as_of - timedelta(days=n)  # noqa: E731
    backup_owner = _pick(people, "Infrastructure", status="active")
    leaver = _pick(people, "Data", status="leaver")
    trader = _pick(people, "Trading", status="active")
    finance = _pick(people, "Finance", status="active")
    base = dict(password_never_expires=True, enabled=True, spns=[], kerberos_encryption="AES256", _clean=True)
    return [
        # Legitimately privileged, covered by a valid exception.
        {**base, "account_name": "svc-backup-prod", "owner_email": backup_owner["email"],
         "department": "Infrastructure", "description": "Backup agent for file servers",
         "created": days(900), "last_logon": days(1), "pwd_last_set": days(60),
         "groups": ["APP-Backup-Users", "Backup Operators"]},
        # The worst case: Domain Admin, owner gone, unused for over a year, Kerberoastable.
        {**base, "account_name": "svc-reporting-legacy", "owner_email": leaver["email"],
         "department": "Data", "description": "Legacy reporting SQL service",
         "created": days(2000), "last_logon": days(420), "pwd_last_set": days(1500),
         "groups": ["APP-Reporting-Users", "Domain Admins"],
         "spns": ["MSSQLSvc/reporting-db01.corp.example:1433"], "kerberos_encryption": "RC4"},
        # No owner on record, but the description and a sibling account point to someone.
        {**base, "account_name": "svc-fixgateway-prod", "owner_email": "",
         "department": "Trading", "description": f"FIX gateway connectivity - owned by {trader['name']}",
         "created": days(700), "last_logon": days(0), "pwd_last_set": days(200),
         "groups": ["APP-Fixgateway-Users"]},
        {**base, "account_name": "svc-fixgateway-uat", "owner_email": trader["email"],
         "department": "Trading", "description": "FIX gateway UAT",
         "created": days(650), "last_logon": days(3), "pwd_last_set": days(120),
         "groups": ["APP-Fixgateway-Users"]},
        # Stale password whose exception has lapsed.
        {**base, "account_name": "svc-recon-batch", "owner_email": finance["email"],
         "department": "Finance", "description": "Nightly reconciliation batch",
         "created": days(1200), "last_logon": days(1), "pwd_last_set": days(800),
         "groups": ["APP-Recon-Users"]},
    ]


def _random_account(rng: random.Random, people: list[dict], as_of: date, app_owners: dict[str, str]) -> dict:
    department = rng.choice(list(DEPARTMENTS))
    app, env = rng.choice(DEPARTMENTS[department]), rng.choice(ENVIRONMENTS)
    name = f"svc-{app}-{env}"
    if rng.random() < 0.08:
        name = rng.choice([f"SVC_{app}_{env}", f"{app}.{env}", f"sa-{app}{env}"])

    active = [p for p in people if p["department"] == department and p["status"] == "active"]
    leavers = [p for p in people if p["department"] == department and p["status"] == "leaver"]
    # Real estates cluster: one person usually owns most accounts for an application.
    usual_owner = app_owners[app] if rng.random() < 0.8 else rng.choice(active)["email"]
    roll = rng.random()
    named = None
    if roll < 0.58:
        owner = usual_owner
    elif roll < 0.68:
        owner = rng.choice([f"  {usual_owner.upper()} ", usual_owner.title(), f"{usual_owner} "])
    elif roll < 0.80:
        owner = rng.choice(leavers)["email"]
    elif roll < 0.92:
        owner = ""
        if rng.random() < 0.5:
            named = rng.choice(active)
    else:
        owner = f"contractor{rng.randint(100, 999)}@external.example"

    description = rng.choice([
        f"Service account for {app} ({env})", f"{app} {env} scheduler", f"Used by {app} integration",
        "legacy - do not touch", "temp account for migration", "",
    ])
    if named:
        description = f"{description} - contact {named['name']}".strip(" -")

    created = as_of - timedelta(days=rng.randint(60, 6 * 365))
    usage = rng.random()
    if usage < 0.70:
        last_logon = as_of - timedelta(days=rng.randint(0, 30))
    elif usage < 0.90:
        last_logon = as_of - timedelta(days=rng.randint(91, 900))
    else:
        last_logon = None
    if last_logon and last_logon < created:
        last_logon = created

    groups = [f"APP-{app.capitalize()}-Users"]
    if app == "backup":
        groups.append("Backup Operators")
    if rng.random() < 0.06:
        groups.append(rng.choice(RISKY_GROUPS))

    # Most accounts are rotated on schedule; about a third have slipped.
    if rng.random() < 0.7:
        pwd_last_set = max(created, as_of - timedelta(days=rng.randint(0, 364)))
    else:
        pwd_last_set = created + timedelta(days=rng.randint(0, (as_of - created).days))

    spns, encryption = [], rng.choice(["AES256", "AES256", ""])
    if rng.random() < 0.2:
        spns = [rng.choice([f"MSSQLSvc/{app}-db01.{DOMAIN}:1433", f"HTTP/{app}.{DOMAIN}"])]
        encryption = "RC4" if rng.random() < 0.4 else "AES256"

    return {
        "account_name": name, "description": description, "owner_email": owner, "department": department,
        "created": created, "last_logon": last_logon,
        "pwd_last_set": pwd_last_set,
        "password_never_expires": rng.random() < 0.55, "enabled": rng.random() < 0.92,
        "groups": groups, "spns": spns, "kerberos_encryption": encryption, "_clean": False,
    }


def _render(rng: random.Random, row: dict) -> dict:
    """Format a row the way a real export might: mostly ISO dates and TRUE/FALSE, but not always."""
    messy = not row["_clean"]

    def fmt_date(value: date | None) -> str:
        if value is None:
            return ""
        roll = rng.random() if messy else 1.0
        if roll < 0.05:
            return value.strftime("%d/%m/%Y")
        if roll < 0.06:
            return "unknown"
        return value.isoformat()

    def fmt_bool(value: bool) -> str:
        if not messy:
            return "TRUE" if value else "FALSE"
        return rng.choice(TRUE_STYLES if value else FALSE_STYLES)

    return {
        "account_name": row["account_name"], "description": row["description"],
        "owner_email": row["owner_email"], "department": row["department"],
        "created": fmt_date(row["created"]), "last_logon": fmt_date(row["last_logon"]),
        "pwd_last_set": fmt_date(row["pwd_last_set"]),
        "password_never_expires": fmt_bool(row["password_never_expires"]), "enabled": fmt_bool(row["enabled"]),
        "groups": ";".join(row["groups"]), "spns": ";".join(row["spns"]),
        "kerberos_encryption": row["kerberos_encryption"],
    }


def _exceptions(people: list[dict], as_of: date) -> list[dict]:
    ciso = f"ciso@{DOMAIN}"
    finance_head = _pick(people, "Finance", status="active", head=True)["email"]
    return [
        {"account": "svc-backup-prod", "rule": "PRIVILEGED", "approved_by": ciso,
         "reason": "Backup Operators required by backup agent; logons restricted to backup servers",
         "expires": (as_of + timedelta(days=120)).isoformat()},
        {"account": "svc-recon-batch", "rule": "PWD_STALE", "approved_by": finance_head,
         "reason": "Rotation blocked until recon platform upgrade",
         "expires": (as_of - timedelta(days=10)).isoformat()},
        {"account": "svc-oldftp-prod", "rule": "DORMANT", "approved_by": ciso,
         "reason": "Kept for annual regulatory file transfer",
         "expires": (as_of + timedelta(days=30)).isoformat()},
        # Invalid on purpose: no approver.
        {"account": "svc-reporting-legacy", "rule": "PRIVILEGED", "approved_by": "",
         "reason": "Needed for legacy reports", "expires": (as_of + timedelta(days=365)).isoformat()},
    ]


def generate(out_dir: str | Path, *, accounts: int = 500, people_per_department: int = 24,
             seed: int = 42, as_of: date | None = None) -> dict[str, Path]:
    as_of = as_of or date.today()
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    people = _people(rng, as_of, people_per_department)
    app_owners = {
        app: rng.choice([p for p in people if p["department"] == dept and p["status"] == "active"])["email"]
        for dept, apps in DEPARTMENTS.items() for app in apps
    }
    rows = _scenarios(people, as_of)
    names = {r["account_name"].lower() for r in rows}
    while len(rows) < accounts:
        row = _random_account(rng, people, as_of, app_owners)
        base, n = row["account_name"], 2
        while row["account_name"].lower() in names:
            row["account_name"], n = f"{base}-{n}", n + 1
        names.add(row["account_name"].lower())
        rows.append(row)

    rendered = [_render(rng, r) for r in rows]
    randoms = [r for r, raw in zip(rendered, rows) if not raw["_clean"]]
    rendered += rng.sample(randoms, k=max(1, len(randoms) // 100))  # exact duplicate rows
    rng.shuffle(rendered)

    paths = {
        "accounts": out / "service_accounts.csv",
        "people": out / "hr_people.csv",
        "exceptions": out / "exceptions.yaml",
    }
    with paths["accounts"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ACCOUNT_FIELDS)
        writer.writeheader()
        writer.writerows(rendered)
    with paths["people"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=HR_FIELDS)
        writer.writeheader()
        for p in people:
            writer.writerow({**p, "leave_date": p["leave_date"].isoformat() if p["leave_date"] else "",
                             "manager_email": p["manager_email"] or ""})
    with paths["exceptions"].open("w", encoding="utf-8") as handle:
        yaml.safe_dump(_exceptions(people, as_of), handle, sort_keys=False)
    return paths
