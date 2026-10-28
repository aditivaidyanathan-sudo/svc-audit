import pytest

from svc_audit.policy import build_policy, load_policy


def test_defaults():
    policy = build_policy()
    assert policy.dormant_days == 90
    assert policy.is_privileged("DOMAIN ADMINS")


def test_overrides_apply():
    assert build_policy({"dormant_days": 30}).dormant_days == 30


def test_unknown_key_is_rejected():
    with pytest.raises(ValueError, match="dormat_days"):
        build_policy({"dormat_days": 30})


@pytest.mark.parametrize("bad", [
    {"dormant_days": 0},
    {"naming_pattern": "("},
    {"severity_weights": {"low": 1}},
    {"priority_thresholds": {"P1": 1}},
])
def test_invalid_values_are_rejected(bad):
    with pytest.raises(ValueError):
        build_policy(bad)


def test_shipped_policy_file_loads():
    assert load_policy("config/policy.yaml").password_max_age_days == 365
