import json

from svc_audit import audit


def test_entries_chain_and_verify(tmp_path):
    log = tmp_path / "audit.jsonl"
    first = audit.append_event(log, {"action": "scan"})
    second = audit.append_event(log, {"action": "note"})
    assert first["prev_hash"] == audit.GENESIS
    assert second["prev_hash"] == first["hash"]
    assert audit.verify_log(log) == []


def test_edited_entry_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    audit.append_event(log, {"action": "decision", "account": "svc-a", "decision": "note", "by": "me", "note": "x"})
    entry = json.loads(log.read_text())
    entry["by"] = "someone else"
    log.write_text(json.dumps(entry) + "\n")
    assert any("edited" in p for p in audit.verify_log(log))


def test_deleted_entry_breaks_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(3):
        audit.append_event(log, {"action": "note", "n": i})
    lines = log.read_text().splitlines()
    log.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert any("chain broken" in p for p in audit.verify_log(log))


def test_latest_owner_confirmation_wins(tmp_path):
    log = tmp_path / "audit.jsonl"
    for owner in ("a@corp.example", "b@corp.example"):
        audit.append_event(log, {"action": "decision", "account": "svc-a", "decision": "owner-confirmed",
                                 "owner": owner, "by": "me", "note": "confirmed by email"})
    assert audit.confirmed_owners(audit.read_log(log))["svc-a"]["owner"] == "b@corp.example"
