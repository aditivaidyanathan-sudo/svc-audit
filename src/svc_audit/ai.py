"""Optional AI-assisted triage: suggest an account's purpose and likely team from its description.

Guardrails:
- Output is labelled UNVERIFIED and is never used to assign an owner or change a finding.
- Only the account name, description, group names and SPNs are sent. No HR data or owner emails.
- Any failure (no key, bad response) returns None and the scan carries on without it.
"""
from __future__ import annotations

import json

from .models import ServiceAccount

DEFAULT_MODEL = "claude-haiku-5-5"

SYSTEM_PROMPT = (
    "You help an identity governance analyst triage service accounts. "
    "From the account details, infer what the account is for and which team most likely runs it. "
    "If the details are too thin to tell, say 'unknown'. "
    'Reply with JSON only: {"purpose": string, "likely_team": string, "confidence": "low"|"medium"|"high"}'
)


def build_prompt(account: ServiceAccount) -> str:
    return (
        f"Account name: {account.name}\n"
        f"Description: {account.description}\n"
        f"Groups: {', '.join(account.groups) or 'none'}\n"
        f"SPNs: {', '.join(account.spns) or 'none'}"
    )


def suggest_purpose(account: ServiceAccount, client=None, model: str = DEFAULT_MODEL) -> str | None:
    if not account.description:
        return None
    try:
        if client is None:
            import anthropic  # optional dependency: pip install svc-audit[ai]

            client = anthropic.Anthropic()
        response = client.messages.create(
            model=model,
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_prompt(account)}],
        )
        text = "".join(getattr(block, "text", "") for block in response.content).strip()
        data = json.loads(text)
        return (
            f"UNVERIFIED: purpose={data.get('purpose', 'unknown')}; "
            f"team={data.get('likely_team', 'unknown')}; model confidence={data.get('confidence', 'low')}"
        )
    except Exception:  # noqa: BLE001 - AI help is optional; never let it break a scan
        return None
