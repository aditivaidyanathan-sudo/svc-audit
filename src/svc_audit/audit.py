"""Append-only, hash-chained audit log (JSON Lines).

Each entry stores the hash of the previous entry, so editing or deleting a
past entry breaks the chain and `verify_log` reports it. This makes tampering
evident, not impossible: in production the log would also be shipped to
write-once storage or a SIEM.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64

DECISIONS = {
    "owner-confirmed": "Owner has confirmed they are accountable for the account",
    "dependency-found": "Account is in use by a dependency; do not disable",
    "retirement-approved": "Owner approves retirement; hand to engineering",
    "exception-requested": "Owner has requested a risk exception",
    "note": "Free-text investigation note",
}


def _digest(entry: dict) -> str:
    payload = {k: v for k, v in entry.items() if k != "hash"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_log(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def append_event(path: str | Path, event: dict, now: datetime | None = None) -> dict:
    path = Path(path)
    entries = read_log(path)
    entry = {
        "ts": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        **event,
        "prev_hash": entries[-1]["hash"] if entries else GENESIS,
    }
    entry["hash"] = _digest(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_log(path: str | Path) -> list[str]:
    path = Path(path)
    if not path.exists():
        return []
    problems: list[str] = []
    previous = GENESIS
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate((l for l in handle if l.strip()), start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"entry {number}: not valid JSON")
                previous = None
                continue
            if entry.get("prev_hash") != previous:
                problems.append(f"entry {number}: chain broken (an earlier entry was changed or removed)")
            if _digest(entry) != entry.get("hash"):
                problems.append(f"entry {number}: content does not match its hash (entry was edited)")
            previous = entry.get("hash")
    return problems


def latest_decisions(entries: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for entry in entries:
        if entry.get("action") == "decision":
            latest[entry["account"]] = entry
    return latest


def confirmed_owners(entries: list[dict]) -> dict[str, dict]:
    confirmed: dict[str, dict] = {}
    for entry in entries:
        if entry.get("action") == "decision" and entry.get("decision") == "owner-confirmed":
            confirmed[entry["account"]] = entry
    return confirmed
