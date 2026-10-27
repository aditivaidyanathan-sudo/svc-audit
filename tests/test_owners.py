from conftest import make_account

from warden.owners import MAX_CONFIDENCE, OwnerInference, app_key


def test_app_key_handles_naming_variants():
    assert app_key("svc-payments-prod") == "payments"
    assert app_key("SVC_payments_batch") == "payments"
    assert app_key("payments.api") == "payments"


def test_person_named_in_description(people):
    target = make_account(owner_email=None, description="Payments feed - owned by Ann Lee")
    top = OwnerInference([target], people).candidates(target)[0]
    assert top.email == "ann.lee@corp.example"
    assert "named in description" in top.reasons


def test_sibling_accounts_point_to_owner(people):
    target = make_account(name="svc-payments-uat", owner_email=None, description="")
    siblings = [make_account(name=f"svc-payments-{env}") for env in ("prod", "api")]
    top = OwnerInference([target, *siblings], people).candidates(target)[0]
    assert top.email == "ann.lee@corp.example"
    assert "owns 2 of 2" in top.reasons[0]


def test_manager_of_departed_owner(people):
    target = make_account(owner_email="bob.gone@corp.example", description="")
    top = OwnerInference([target], people).candidates(target)[0]
    assert top.email == "head.finance@corp.example"
    assert any("manager of departed owner" in r for r in top.reasons)


def test_confidence_is_capped_and_never_certain(people):
    target = make_account(name="svc-payments-uat", owner_email=None, description="owned by Ann Lee ann.lee")
    siblings = [make_account(name="svc-payments-prod")]
    top = OwnerInference([target, *siblings], people).candidates(target)[0]
    assert top.confidence == MAX_CONFIDENCE < 1.0


def test_weak_signals_are_dropped(people):
    target = make_account(owner_email=None, description="", department=None)
    assert OwnerInference([target], people).candidates(target) == []
