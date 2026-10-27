from conftest import make_account

from warden.models import Finding
from warden.report import CONFIRM, DISABLE, ESCALATE, build_queue, recommend_actions, risk_score


def f(rule, severity="medium", suppressed=None):
    return Finding("svc-a", rule, severity, "detail", suppressed)


def test_owner_must_be_confirmed_before_disabling():
    assert recommend_actions([f("DORMANT"), f("NO_OWNER", "high")]) == [CONFIRM, DISABLE]


def test_privileged_problems_escalate_first():
    actions = recommend_actions([f("NO_OWNER", "high"), f("PRIVILEGED", "high")])
    assert actions[0] == ESCALATE


def test_suppressed_findings_do_not_count(policy):
    assert risk_score([f("PRIVILEGED", "high", "exception"), f("DORMANT")], policy) == 3


def test_queue_priorities_and_order(policy):
    accounts = [make_account(name="svc-low"), make_account(name="svc-crit"), make_account(name="svc-clean")]
    findings = {
        "svc-low": [Finding("svc-low", "NAMING", "low", "d")],
        "svc-crit": [Finding("svc-crit", "PRIVILEGED_UNGOVERNED", "critical", "d")],
        "svc-clean": [],
    }
    queue = build_queue(accounts, findings, policy)
    assert [(q.account, q.priority) for q in queue] == [("svc-crit", "P1"), ("svc-low", "P4")]
