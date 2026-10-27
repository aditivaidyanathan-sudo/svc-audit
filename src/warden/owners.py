"""Suggest likely owners for accounts with no valid owner.

Suggestions are evidence for a human to confirm, never an assignment. Each
candidate carries a confidence score and the reasons behind it, so whoever
follows up knows who to ask first and why.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .models import Person, ServiceAccount

WEIGHT_NAMED_IN_DESCRIPTION = 0.6
WEIGHT_SIBLING_OWNER = 0.6  # scaled by the share of sibling accounts this person owns
WEIGHT_MANAGER_OF_LEAVER = 0.4
WEIGHT_DEPARTMENT_HEAD = 0.15
MAX_CONFIDENCE = 0.95  # inference is never certain
MIN_CONFIDENCE = 0.1  # below this a suggestion is noise, not evidence

NAME_PREFIXES = {"svc", "sa", "app", "srv"}


@dataclass
class OwnerCandidate:
    email: str
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def band(self) -> str:
        if self.confidence >= 0.7:
            return "high"
        if self.confidence >= 0.4:
            return "medium"
        return "low"

    def __str__(self) -> str:
        return f"{self.email} [{self.band} {self.confidence:.2f}: {'; '.join(self.reasons)}]"


def app_key(name: str) -> str | None:
    """'svc-payments-prod', 'SVC_payments_batch' and 'payments.api' all map to 'payments'."""
    parts = [p for p in re.split(r"[-_.]", name.lower()) if p]
    if parts and parts[0] in NAME_PREFIXES:
        parts = parts[1:]
    return parts[0] if parts else None


class OwnerInference:
    def __init__(self, accounts: list[ServiceAccount], people: dict[str, Person]):
        self.people = people
        self.active = [p for p in people.values() if p.is_active]
        self.by_app: dict[str, list[ServiceAccount]] = {}
        for account in accounts:
            key = app_key(account.name)
            if key:
                self.by_app.setdefault(key, []).append(account)

    def _valid_owner(self, account: ServiceAccount) -> Person | None:
        person = self.people.get(account.owner_email) if account.owner_email else None
        return person if person and person.is_active else None

    def candidates(self, account: ServiceAccount, limit: int = 3) -> list[OwnerCandidate]:
        found: dict[str, OwnerCandidate] = {}

        def credit(email: str, weight: float, reason: str) -> None:
            candidate = found.setdefault(email, OwnerCandidate(email))
            candidate.confidence += weight
            candidate.reasons.append(reason)

        # 1. A named person in the free-text description.
        description = account.description.lower()
        if description:
            for person in self.active:
                local_part = person.email.split("@")[0]
                if (person.name and person.name.lower() in description) or local_part in description:
                    credit(person.email, WEIGHT_NAMED_IN_DESCRIPTION, "named in description")

        # 2. Who owns the other accounts for the same application?
        key = app_key(account.name)
        siblings = [a for a in self.by_app.get(key, []) if a.name != account.name]
        owners = Counter(o.email for a in siblings if (o := self._valid_owner(a)))
        if owners:
            total = len(siblings)
            for email, count in owners.items():
                credit(email, WEIGHT_SIBLING_OWNER * count / total, f"owns {count} of {total} other '{key}' accounts")

        # 3. The departed owner's manager inherits the question.
        recorded = self.people.get(account.owner_email) if account.owner_email else None
        if recorded and not recorded.is_active and recorded.manager_email:
            manager = self.people.get(recorded.manager_email)
            if manager and manager.is_active:
                credit(manager.email, WEIGHT_MANAGER_OF_LEAVER, f"manager of departed owner {recorded.name}")

        # 4. Fallback: the head of the recorded department.
        if account.department:
            for person in self.active:
                if person.department == account.department and person.manager_email is None:
                    credit(person.email, WEIGHT_DEPARTMENT_HEAD, f"head of {account.department}")

        for candidate in found.values():
            candidate.confidence = round(min(candidate.confidence, MAX_CONFIDENCE), 2)
        kept = [c for c in found.values() if c.confidence >= MIN_CONFIDENCE]
        return sorted(kept, key=lambda c: (-c.confidence, c.email))[:limit]
