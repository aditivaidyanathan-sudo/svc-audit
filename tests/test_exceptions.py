from datetime import timedelta

import yaml
from conftest import AS_OF

from svc_audit.exceptions import RiskException, apply_exceptions, load_exceptions
from svc_audit.models import Finding


def exc(rule="PRIVILEGED", days=30, account="svc-a"):
    return RiskException(account, rule, "reason", "ciso@corp.example", AS_OF + timedelta(days=days))


def findings(*rules, severity="high"):
    return {"svc-a": [Finding("svc-a", r, severity, "detail") for r in rules]}


def test_active_exception_suppresses_matching_finding_only():
    found = findings("PRIVILEGED", "DORMANT")
    outcome = apply_exceptions(found, [exc()], AS_OF)
    assert outcome.applied
    assert [f.active for f in found["svc-a"]] == [False, True]


def test_expired_exception_raises_new_finding():
    found = findings("PRIVILEGED")
    outcome = apply_exceptions(found, [exc(days=-1)], AS_OF)
    assert outcome.expired
    assert found["svc-a"][0].active
    assert found["svc-a"][-1].rule == "EXCEPTION_EXPIRED"


def test_exception_without_matching_finding_is_unused():
    outcome = apply_exceptions(findings("DORMANT"), [exc(), exc(account="svc-gone")], AS_OF)
    assert len(outcome.unused) == 2


def test_critical_findings_cannot_be_waived():
    found = findings("PRIVILEGED_UNGOVERNED", severity="critical")
    outcome = apply_exceptions(found, [exc(rule="PRIVILEGED_UNGOVERNED")], AS_OF)
    assert outcome.refused and found["svc-a"][0].active


def test_loader_rejects_incomplete_entries(tmp_path):
    path = tmp_path / "exceptions.yaml"
    path.write_text(yaml.safe_dump([
        {"account": "svc-a", "rule": "privileged", "reason": "r", "approved_by": "ciso", "expires": "2027-01-01"},
        {"account": "svc-b", "rule": "DORMANT", "reason": "r", "approved_by": "", "expires": "2027-01-01"},
        {"account": "svc-c", "rule": "DORMANT", "reason": "r", "approved_by": "x", "expires": "soon"},
    ]))
    exceptions, issues = load_exceptions(path)
    assert [e.account for e in exceptions] == ["svc-a"]
    assert exceptions[0].rule == "PRIVILEGED"
    assert len(issues) == 2


def test_missing_file_means_no_exceptions(tmp_path):
    assert load_exceptions(tmp_path / "none.yaml") == ([], [])
