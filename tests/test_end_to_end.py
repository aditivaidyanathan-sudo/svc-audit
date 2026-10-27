"""Runs the real CLI on generated data and checks the scripted scenarios."""
import csv

import pytest

from warden.cli import main
from warden.generate import generate

AS_OF = "2026-10-21"


@pytest.fixture
def workspace(tmp_path):
    from datetime import date

    generate(tmp_path / "data", accounts=200, seed=7, as_of=date.fromisoformat(AS_OF))
    return tmp_path


def scan(ws):
    return main([
        "scan", "--accounts", str(ws / "data/service_accounts.csv"), "--hr", str(ws / "data/hr_people.csv"),
        "--policy", "config/policy.yaml", "--exceptions", str(ws / "data/exceptions.yaml"),
        "--audit-log", str(ws / "audit.jsonl"), "--out", str(ws / "out"), "--as-of", AS_OF,
    ])


def queue(ws):
    with open(ws / "out/remediation_queue.csv", newline="") as handle:
        return {row["account"]: row for row in csv.DictReader(handle)}


def test_generation_is_reproducible(tmp_path):
    from datetime import date

    a = generate(tmp_path / "a", accounts=50, seed=1, as_of=date(2026, 1, 1))
    b = generate(tmp_path / "b", accounts=50, seed=1, as_of=date(2026, 1, 1))
    assert a["accounts"].read_text() == b["accounts"].read_text()


def test_scan_produces_outputs_and_audit_entry(workspace):
    assert scan(workspace) == 0
    for name in ("remediation_queue.csv", "findings.csv", "data_quality.csv", "report.md"):
        assert (workspace / "out" / name).exists()
    assert '"action": "scan"' in (workspace / "audit.jsonl").read_text()


def test_scenarios(workspace):
    scan(workspace)
    q = queue(workspace)
    assert q["svc-reporting-legacy"]["priority"] == "P1"
    assert "PRIVILEGED_UNGOVERNED" in q["svc-reporting-legacy"]["rules"]
    assert "named in description" in q["svc-fixgateway-prod"]["owner_candidates"]
    assert "EXCEPTION_EXPIRED" in q["svc-recon-batch"]["rules"]
    assert "PRIVILEGED" not in q.get("svc-backup-prod", {}).get("rules", "")


def test_confirmed_owner_closes_the_gap_on_next_scan(workspace):
    scan(workspace)
    assert "NO_OWNER" in queue(workspace)["svc-fixgateway-prod"]["rules"]
    hr = (workspace / "data/hr_people.csv").read_text().splitlines()
    owner = next(line.split(",")[0] for line in hr[1:] if ",active," in line)
    assert main(["decide", "--audit-log", str(workspace / "audit.jsonl"), "--account", "svc-fixgateway-prod",
                 "--decision", "owner-confirmed", "--owner", owner, "--by", "analyst",
                 "--note", "Confirmed by email"]) == 0
    scan(workspace)
    row = queue(workspace).get("svc-fixgateway-prod", {})
    assert "NO_OWNER" not in row.get("rules", "")


def test_scan_refuses_tampered_log(workspace):
    scan(workspace)
    log = workspace / "audit.jsonl"
    log.write_text(log.read_text().replace('"scan"', '"edited"'))
    assert scan(workspace) == 2
