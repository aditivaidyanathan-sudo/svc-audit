from datetime import date

import pytest

from warden.loader import load_accounts, load_people
from warden.models import ACCOUNT_FIELDS, HR_FIELDS


def write_csv(path, header, rows):
    path.write_text("\n".join([",".join(header)] + [",".join(r) for r in rows]) + "\n", encoding="utf-8")
    return path


def row(**values):
    base = dict(account_name="svc-a-prod", description="d", owner_email="ann@corp.example", department="Finance",
                created="2024-01-01", last_logon="2026-10-01", pwd_last_set="2026-01-01",
                password_never_expires="FALSE", enabled="TRUE", groups="G1;G2", spns="", kerberos_encryption="aes256")
    base.update(values)
    return [base[f] for f in ACCOUNT_FIELDS]


def problems(issues):
    return [i.problem for i in issues]


def test_clean_row_parses(tmp_path):
    accounts, issues = load_accounts(write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [row()]))
    assert issues == []
    a = accounts[0]
    assert a.created == date(2024, 1, 1)
    assert a.groups == ["G1", "G2"] and a.spns == []
    assert a.enabled is True and a.password_never_expires is False
    assert a.kerberos_encryption == "AES256"


def test_uk_dates_and_ambiguity_warning(tmp_path):
    accounts, issues = load_accounts(
        write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [row(created="04/03/2025", last_logon="25/12/2025")])
    )
    assert accounts[0].created == date(2025, 3, 4)
    assert accounts[0].last_logon == date(2025, 12, 25)
    assert problems(issues) == ["ambiguous date; interpreted as DD/MM/YYYY (UK)"]  # only 04/03 is ambiguous


def test_unparseable_date_becomes_unknown(tmp_path):
    accounts, issues = load_accounts(write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [row(last_logon="unknown")]))
    assert accounts[0].last_logon is None
    assert issues[0].level == "error"


def test_boolean_variants_and_unreadable_falls_back_to_riskier_value(tmp_path):
    accounts, issues = load_accounts(write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [
        row(account_name="svc-a-1", enabled="yes", password_never_expires="0"),
        row(account_name="svc-a-2", enabled="maybe", password_never_expires="?"),
    ]))
    assert accounts[0].enabled is True and accounts[0].password_never_expires is False
    assert accounts[1].enabled is True and accounts[1].password_never_expires is True
    assert len(issues) == 2


def test_owner_email_normalised_with_warning(tmp_path):
    accounts, issues = load_accounts(
        write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [row(owner_email="  ANN@Corp.Example ")])
    )
    assert accounts[0].owner_email == "ann@corp.example"
    assert issues[0].level == "warning"


def test_non_email_owner_treated_as_missing(tmp_path):
    accounts, issues = load_accounts(write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [row(owner_email="Ann Lee")]))
    assert accounts[0].owner_email is None
    assert "not an email" in issues[0].problem


def test_duplicates_and_blank_names_are_skipped_and_reported(tmp_path):
    accounts, issues = load_accounts(write_csv(tmp_path / "a.csv", ACCOUNT_FIELDS, [
        row(), row(account_name="SVC-A-PROD"), row(account_name=""),
    ]))
    assert len(accounts) == 1
    assert [i.row for i in issues] == [3, 4]


def test_missing_column_fails_loudly(tmp_path):
    header = [f for f in ACCOUNT_FIELDS if f != "enabled"]
    with pytest.raises(ValueError, match="enabled"):
        load_accounts(write_csv(tmp_path / "a.csv", header, []))


def test_people_feed(tmp_path):
    path = write_csv(tmp_path / "hr.csv", HR_FIELDS, [
        ["ann@corp.example", "Ann", "Finance", "active", "", "boss@corp.example"],
        ["bob@corp.example", "Bob", "Finance", "LEAVER", "2026-01-01", "boss@corp.example"],
        ["cat@corp.example", "Cat", "Finance", "contractor", "", ""],
    ])
    people, issues = load_people(path)
    assert people["ann@corp.example"].is_active
    assert not people["bob@corp.example"].is_active
    assert not people["cat@corp.example"].is_active
    assert "unknown status" in issues[0].problem
