"""Command-line interface.

    warden generate    create synthetic demo data
    warden scan        evaluate accounts and build the remediation queue (read-only)
    warden decide      record an investigation decision in the audit log
    warden verify-log  check the audit log has not been altered
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import date
from pathlib import Path

from . import audit
from .exceptions import apply_exceptions, load_exceptions
from .generate import generate
from .loader import load_accounts, load_people
from .owners import OwnerInference
from .policy import load_policy
from .report import build_queue, write_outputs
from .rules import evaluate_all, has_ownership_gap


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_generate(args: argparse.Namespace) -> int:
    paths = generate(args.out, accounts=args.accounts, seed=args.seed, as_of=args.as_of)
    for label, path in paths.items():
        print(f"wrote {label}: {path}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    as_of = args.as_of or date.today()

    problems = audit.verify_log(args.audit_log)
    if problems:
        print("Audit log failed verification; refusing to scan on top of it:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    entries = audit.read_log(args.audit_log)

    policy = load_policy(args.policy)
    accounts, issues = load_accounts(args.accounts)
    people, people_issues = load_people(args.hr)
    exceptions, exception_issues = load_exceptions(args.exceptions)
    issues += people_issues + exception_issues

    # Owner confirmations recorded earlier take precedence over the export.
    confirmed = audit.confirmed_owners(entries)
    overrides = 0
    for account in accounts:
        if account.name in confirmed:
            account.owner_email = confirmed[account.name]["owner"]
            overrides += 1

    findings = evaluate_all(accounts, people, policy, as_of)
    outcome = apply_exceptions(findings, exceptions, as_of)

    inference = OwnerInference(accounts, people)
    candidates = {a.name: inference.candidates(a) for a in accounts if has_ownership_gap(findings[a.name])}

    ai_suggestions: dict[str, str] = {}
    if args.ai:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("--ai requested but ANTHROPIC_API_KEY is not set; continuing without AI suggestions.")
        else:
            from .ai import suggest_purpose

            for account in accounts:
                if account.name in candidates:
                    suggestion = suggest_purpose(account)
                    if suggestion:
                        ai_suggestions[account.name] = suggestion

    queue = build_queue(accounts, findings, policy, candidates, audit.latest_decisions(entries), ai_suggestions)

    inputs = {Path(p).name: _sha256(Path(p)) for p in (args.accounts, args.hr, args.policy, args.exceptions)
              if p and Path(p).exists()}
    meta = {"as_of": as_of.isoformat(), "accounts": len(accounts), "owner_overrides": overrides, "inputs": inputs}
    paths = write_outputs(args.out, queue, findings, issues, outcome, meta)

    counts = {p: sum(q.priority == p for q in queue) for p in ("P1", "P2", "P3", "P4")}
    audit.append_event(args.audit_log, {
        "action": "scan", "as_of": as_of.isoformat(), "accounts": len(accounts), "queue": len(queue),
        "priorities": counts, "data_quality_issues": len(issues), "ai_used": bool(ai_suggestions),
        "inputs": inputs,
    })

    print(f"Scanned {len(accounts)} accounts as of {as_of}: {len(queue) - counts['P4']} need action "
          f"(P1 {counts['P1']}, P2 {counts['P2']}, P3 {counts['P3']}), {counts['P4']} hygiene only.")
    print(f"{len(issues)} data-quality issues. Nothing was changed.")
    print(f"Report: {paths['report']}")
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    if args.decision == "owner-confirmed" and (not args.owner or "@" not in args.owner):
        print("owner-confirmed needs --owner with the confirming person's email.", file=sys.stderr)
        return 1
    event = {"action": "decision", "account": args.account, "decision": args.decision,
             "by": args.by, "note": args.note}
    if args.owner:
        event["owner"] = args.owner.strip().lower()
    entry = audit.append_event(args.audit_log, event)
    print(f"Recorded {args.decision} for {args.account} (entry {entry['hash'][:12]}).")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    problems = audit.verify_log(args.audit_log)
    if problems:
        for problem in problems:
            print(problem)
        return 1
    print(f"Audit log OK ({len(audit.read_log(args.audit_log))} entries).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    as_of = dict(type=date.fromisoformat, default=None, help="evaluation date YYYY-MM-DD (default: today)")
    log = dict(default="audit/audit.jsonl", help="audit log path (default: audit/audit.jsonl)")

    g = sub.add_parser("generate", help="create synthetic demo data")
    g.add_argument("--out", default="data")
    g.add_argument("--accounts", type=int, default=500)
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--as-of", **as_of)
    g.set_defaults(func=cmd_generate)

    s = sub.add_parser("scan", help="evaluate accounts and build the remediation queue")
    s.add_argument("--accounts", default="data/service_accounts.csv")
    s.add_argument("--hr", default="data/hr_people.csv")
    s.add_argument("--policy", default="config/policy.yaml")
    s.add_argument("--exceptions", default="data/exceptions.yaml")
    s.add_argument("--audit-log", **log)
    s.add_argument("--out", default="out")
    s.add_argument("--as-of", **as_of)
    s.add_argument("--ai", action="store_true", help="add UNVERIFIED AI purpose suggestions (needs ANTHROPIC_API_KEY)")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("decide", help="record an investigation decision")
    d.add_argument("--account", required=True)
    d.add_argument("--decision", required=True, choices=sorted(audit.DECISIONS))
    d.add_argument("--by", required=True, help="who is recording the decision")
    d.add_argument("--note", required=True, help="evidence or reason for the decision")
    d.add_argument("--owner", help="confirmed owner email (for owner-confirmed)")
    d.add_argument("--audit-log", **log)
    d.set_defaults(func=cmd_decide)

    v = sub.add_parser("verify-log", help="check the audit log hash chain")
    v.add_argument("--audit-log", **log)
    v.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
