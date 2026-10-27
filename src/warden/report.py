"""Turn findings into a prioritised remediation queue and write the outputs."""
from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .exceptions import ExceptionOutcome
from .models import DataQualityIssue, Finding, ServiceAccount
from .owners import OwnerCandidate
from .policy import Policy

ESCALATE = "Escalate to IAM engineering"
CONFIRM = "Confirm owner"
DISABLE = "Disable after dependency check"
ROTATE = "Schedule credential rotation"
RENEW = "Renew or close exception"
REVIEW = "Review with owner"

# Order matters: privileged and Kerberos exposure go to engineering first; nothing is
# disabled or rotated until someone owns the decision, because both can break a live service.
ACTION_ORDER = [ESCALATE, CONFIRM, DISABLE, ROTATE, RENEW, REVIEW]

RULE_ACTIONS = {
    "PRIVILEGED_UNGOVERNED": ESCALATE,
    "PRIVILEGED": ESCALATE,
    "WEAK_KERBEROS": ESCALATE,
    "PWD_STALE": ROTATE,
    "NO_OWNER": CONFIRM,
    "OWNER_LEFT": CONFIRM,
    "OWNER_UNKNOWN": CONFIRM,
    "DORMANT": DISABLE,
    "NEVER_USED": DISABLE,
    "EXCEPTION_EXPIRED": RENEW,
}


@dataclass
class QueueItem:
    account: str
    department: str
    owner: str
    priority: str
    risk_score: int
    primary_action: str
    actions: list[str]
    rules: list[str]
    owner_candidates: list[OwnerCandidate] = field(default_factory=list)
    last_decision: str = ""
    ai_suggestion: str = ""


def risk_score(findings: list[Finding], policy: Policy) -> int:
    return sum(policy.severity_weights[f.severity] for f in findings if f.active)


def priority_for(findings: list[Finding], score: int, policy: Policy) -> str:
    thresholds = policy.priority_thresholds
    if any(f.severity == "critical" and f.active for f in findings) or score >= thresholds["P1"]:
        return "P1"
    if score >= thresholds["P2"]:
        return "P2"
    if score >= thresholds["P3"]:
        return "P3"
    return "P4"


def recommend_actions(findings: list[Finding]) -> list[str]:
    wanted = {RULE_ACTIONS.get(f.rule, REVIEW) for f in findings if f.active}
    return [action for action in ACTION_ORDER if action in wanted]


def build_queue(
    accounts: list[ServiceAccount],
    findings: dict[str, list[Finding]],
    policy: Policy,
    candidates: dict[str, list[OwnerCandidate]] | None = None,
    decisions: dict[str, dict] | None = None,
    ai_suggestions: dict[str, str] | None = None,
) -> list[QueueItem]:
    candidates = candidates or {}
    decisions = decisions or {}
    ai_suggestions = ai_suggestions or {}
    queue: list[QueueItem] = []

    for account in accounts:
        active = [f for f in findings.get(account.name, []) if f.active]
        if not active:
            continue
        score = risk_score(active, policy)
        actions = recommend_actions(active)
        decision = decisions.get(account.name)
        queue.append(
            QueueItem(
                account=account.name,
                department=account.department or "",
                owner=account.owner_email or "",
                priority=priority_for(active, score, policy),
                risk_score=score,
                primary_action=actions[0],
                actions=actions,
                rules=[f.rule for f in active],
                owner_candidates=candidates.get(account.name, []),
                last_decision=(
                    f"{decision['decision']} by {decision['by']} on {decision['ts'][:10]}: {decision['note']}"
                    if decision else ""
                ),
                ai_suggestion=ai_suggestions.get(account.name, ""),
            )
        )
    return sorted(queue, key=lambda q: (q.priority, -q.risk_score, q.account))


def _write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def write_outputs(
    out_dir: str | Path,
    queue: list[QueueItem],
    findings: dict[str, list[Finding]],
    issues: list[DataQualityIssue],
    exceptions: ExceptionOutcome,
    meta: dict,
) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "queue": out / "remediation_queue.csv",
        "findings": out / "findings.csv",
        "data_quality": out / "data_quality.csv",
        "report": out / "report.md",
    }

    _write_csv(
        paths["queue"],
        ["priority", "risk_score", "account", "department", "owner", "primary_action", "all_actions",
         "rules", "owner_candidates", "last_decision", "ai_suggestion_unverified"],
        [[q.priority, q.risk_score, q.account, q.department, q.owner, q.primary_action, "; ".join(q.actions),
          "; ".join(q.rules), " | ".join(str(c) for c in q.owner_candidates), q.last_decision, q.ai_suggestion]
         for q in queue],
    )
    _write_csv(
        paths["findings"],
        ["account", "rule", "severity", "detail", "suppressed_by"],
        [[f.account, f.rule, f.severity, f.detail, f.suppressed_by or ""]
         for items in findings.values() for f in items],
    )
    _write_csv(
        paths["data_quality"],
        ["source", "row", "field", "value", "level", "problem"],
        [[i.source, i.row, i.field, i.value, i.level, i.problem] for i in issues],
    )
    paths["report"].write_text(render_markdown(queue, findings, issues, exceptions, meta), encoding="utf-8")
    return paths


def render_markdown(
    queue: list[QueueItem],
    findings: dict[str, list[Finding]],
    issues: list[DataQualityIssue],
    exceptions: ExceptionOutcome,
    meta: dict,
) -> str:
    all_findings = [f for items in findings.values() for f in items]
    active = [f for f in all_findings if f.active]
    priorities = Counter(q.priority for q in queue)
    actions = Counter(q.primary_action for q in queue)

    lines = [
        "# Warden service-account review",
        "",
        f"- **As of:** {meta['as_of']}",
        f"- **Accounts scanned:** {meta['accounts']}",
        f"- **Accounts needing action (P1–P3):** {len(queue) - priorities['P4']} "
        f"(P1 {priorities['P1']}, P2 {priorities['P2']}, P3 {priorities['P3']})",
        f"- **Hygiene only (P4):** {priorities['P4']}",
        f"- **Active findings:** {len(active)} ({len(all_findings) - len(active)} suppressed by approved exceptions)",
        f"- **Data-quality issues:** {len(issues)}",
        f"- **Owner decisions applied from audit log:** {meta.get('owner_overrides', 0)}",
        "",
        "> This run changed nothing. Warden is read-only: it reports and recommends. "
        "Disabling accounts, rotating credentials and removing group memberships are "
        "production changes for IAM engineering.",
        "",
        "## Next actions",
        "",
        "| Action | Accounts |",
        "|---|---|",
    ]
    lines += [f"| {a} | {actions[a]} |" for a in ACTION_ORDER if actions[a]]

    lines += ["", "## Findings by rule", "", "| Rule | Count |", "|---|---|"]
    lines += [f"| {rule} | {count} |" for rule, count in Counter(f.rule for f in active).most_common()]

    lines += ["", "## Top of the queue", "", "| Priority | Score | Account | Primary action | Rules |",
              "|---|---|---|---|---|"]
    lines += [f"| {q.priority} | {q.risk_score} | `{q.account}` | {q.primary_action} | {', '.join(q.rules)} |"
              for q in queue[:15]]

    owner_items = [q for q in queue if q.owner_candidates][:10]
    if owner_items:
        lines += ["", "## Suggested owners to contact", "",
                  "Suggestions only. Each must be confirmed by the person before it is recorded "
                  "(`warden decide --decision owner-confirmed`).", ""]
        for q in owner_items:
            lines.append(f"- `{q.account}`")
            lines += [f"  - {c}" for c in q.owner_candidates]

    lines += ["", "## Exceptions", ""]
    if not any([exceptions.applied, exceptions.expired, exceptions.unused, exceptions.refused]):
        lines.append("No exceptions on file.")
    for title, items in [
        ("Applied", exceptions.applied),
        ("Expired (now raised as findings)", exceptions.expired),
        ("Refused (critical findings cannot be waived)", exceptions.refused),
        ("Unused (account or finding no longer exists; consider closing)", exceptions.unused),
    ]:
        if items:
            lines.append(f"**{title}**")
            lines += [f"- {e.label()}" for e in items]
            lines.append("")

    lines += ["", "## Data quality", ""]
    if issues:
        lines += ["| Problem | Count |", "|---|---|"]
        lines += [f"| {p} | {c} |" for p, c in Counter(i.problem for i in issues).most_common()]
        lines += ["", "Full list in `data_quality.csv`."]
    else:
        lines.append("No issues found.")

    if meta.get("inputs"):
        lines += ["", "## Inputs (SHA-256)", ""]
        lines += [f"- `{name}`: `{digest}`" for name, digest in meta["inputs"].items()]

    return "\n".join(lines) + "\n"
