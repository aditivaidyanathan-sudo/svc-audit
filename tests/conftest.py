from datetime import date, timedelta

import pytest

from warden.models import Person, ServiceAccount
from warden.policy import build_policy

AS_OF = date(2026, 10, 21)


def days_ago(n: int) -> date:
    return AS_OF - timedelta(days=n)


def make_account(**overrides) -> ServiceAccount:
    """A healthy, well-governed account. Tests override one thing at a time."""
    values = dict(
        name="svc-payments-prod",
        description="Payments API",
        owner_email="ann.lee@corp.example",
        department="Finance",
        created=days_ago(400),
        last_logon=days_ago(1),
        pwd_last_set=days_ago(30),
        password_never_expires=False,
        enabled=True,
        groups=["APP-Payments-Users"],
        spns=[],
        kerberos_encryption="AES256",
    )
    values.update(overrides)
    return ServiceAccount(**values)


@pytest.fixture
def people() -> dict[str, Person]:
    return {
        "head.finance@corp.example": Person("head.finance@corp.example", "Hana Head", "Finance", "active"),
        "ann.lee@corp.example": Person(
            "ann.lee@corp.example", "Ann Lee", "Finance", "active", manager_email="head.finance@corp.example"
        ),
        "bob.gone@corp.example": Person(
            "bob.gone@corp.example", "Bob Gone", "Finance", "leaver", days_ago(100), "head.finance@corp.example"
        ),
    }


@pytest.fixture
def policy():
    return build_policy()
