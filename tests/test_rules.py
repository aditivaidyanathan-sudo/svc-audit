from conftest import AS_OF, days_ago, make_account

from warden.rules import evaluate_account


def rules_for(account, people, policy):
    return {f.rule for f in evaluate_account(account, people, policy, AS_OF)}


def test_healthy_account_has_no_findings(people, policy):
    assert rules_for(make_account(), people, policy) == set()


def test_dormant_only_after_threshold(people, policy):
    assert "DORMANT" in rules_for(make_account(last_logon=days_ago(91)), people, policy)
    assert "DORMANT" not in rules_for(make_account(last_logon=days_ago(90)), people, policy)


def test_never_used_respects_grace_period(people, policy):
    assert "NEVER_USED" in rules_for(make_account(last_logon=None, created=days_ago(31)), people, policy)
    assert "NEVER_USED" not in rules_for(make_account(last_logon=None, created=days_ago(10)), people, policy)


def test_never_used_flagged_when_creation_date_unknown(people, policy):
    assert "NEVER_USED" in rules_for(make_account(last_logon=None, created=None), people, policy)


def test_disabled_accounts_skip_usage_and_password_rules(people, policy):
    account = make_account(enabled=False, last_logon=days_ago(500), pwd_last_set=days_ago(900),
                           password_never_expires=True)
    assert rules_for(account, people, policy) == set()


def test_ownership_rules(people, policy):
    assert "NO_OWNER" in rules_for(make_account(owner_email=None), people, policy)
    assert "OWNER_LEFT" in rules_for(make_account(owner_email="bob.gone@corp.example"), people, policy)
    assert "OWNER_UNKNOWN" in rules_for(make_account(owner_email="x@external.example"), people, policy)


def test_privileged_group_match_is_case_insensitive(people, policy):
    assert "PRIVILEGED" in rules_for(make_account(groups=["domain admins"]), people, policy)


def test_weak_kerberos_needs_an_spn(people, policy):
    assert "WEAK_KERBEROS" in rules_for(make_account(spns=["MSSQLSvc/db"], kerberos_encryption="RC4"), people, policy)
    assert "WEAK_KERBEROS" not in rules_for(make_account(kerberos_encryption="RC4"), people, policy)


def test_stale_and_unknown_password_age(people, policy):
    assert "PWD_STALE" in rules_for(make_account(pwd_last_set=days_ago(366)), people, policy)
    assert "PWD_STALE" in rules_for(make_account(pwd_last_set=None), people, policy)


def test_privileged_plus_governance_gap_is_critical(people, policy):
    findings = evaluate_account(
        make_account(groups=["Domain Admins"], owner_email="bob.gone@corp.example"), people, policy, AS_OF
    )
    critical = [f for f in findings if f.rule == "PRIVILEGED_UNGOVERNED"]
    assert critical and critical[0].severity == "critical"
    assert "OWNER_LEFT" in critical[0].detail


def test_well_governed_privileged_account_is_not_critical(people, policy):
    assert "PRIVILEGED_UNGOVERNED" not in rules_for(make_account(groups=["Domain Admins"]), people, policy)


def test_naming_and_description(people, policy):
    rules = rules_for(make_account(name="SVC_Payments", description=""), people, policy)
    assert {"NAMING", "NO_DESCRIPTION"} <= rules
