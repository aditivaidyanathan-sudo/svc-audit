# Warden

A read-only governance scanner for service accounts.

Warden takes a directory export of service accounts and an HR feed, finds accounts that are dormant, unowned, over-privileged or carrying weak credentials, suggests who probably owns them, and produces a prioritised remediation queue with a tamper-evident audit trail.

It does not change anything. That is deliberate (see [What Warden deliberately doesn't do](#what-warden-deliberately-doesnt-do)).

## Why

Service accounts tend to outlive the people and projects that created them. In most estates nobody can say, for every machine identity, what it is for, who owns it, what it can access and when it should be retired. Machine identities are also multiplying as AI agents get their own credentials. Warden is a working model of the first step: find the gaps, establish ownership, and record every decision.

## Quick start

```bash
pip install -e ".[dev]"

warden generate --out data       # synthetic, deliberately messy demo data
warden scan                      # writes out/report.md and three CSVs
warden verify-log                # checks the audit log hash chain
pytest -q
```

Recording the outcome of an investigation:

```bash
warden decide --account svc-fixgateway-prod --decision owner-confirmed \
  --owner victor.xu@corp.example --by aditi --note "Confirmed by email, 21 Oct"
warden scan                      # the confirmed owner now overrides the export
```

Decision types: `owner-confirmed`, `dependency-found`, `retirement-approved`, `exception-requested`, `note`. Every decision needs `--by` and `--note`.

## What a scan produces

| File | Contents |
|---|---|
| `out/report.md` | Summary, next actions, top of the queue, suggested owners, exceptions, data quality |
| `out/remediation_queue.csv` | One row per account needing action: priority, score, primary action, owner candidates, last decision |
| `out/findings.csv` | Every finding with its reason, including those suppressed by an exception |
| `out/data_quality.csv` | Every input problem, traced to file, row and field |
| `audit/audit.jsonl` | Append-only, hash-chained log of scans and decisions |

From the demo data (500 accounts):

```
Scanned 500 accounts as of 2026-10-21: 283 need action (P1 36, P2 156, P3 91), 150 hygiene only.
102 data-quality issues. Nothing was changed.
```

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `NO_OWNER` | high | No owner recorded |
| `OWNER_LEFT` | high | Owner is not active in the HR feed |
| `OWNER_UNKNOWN` | medium | Owner not found in the HR feed (contractor, typo, external) |
| `PRIVILEGED` | high | Member of a privileged group |
| `PRIVILEGED_UNGOVERNED` | critical | Privileged *and* unowned, dormant, unused, stale or Kerberoastable |
| `DORMANT` | medium | Enabled, no logon for longer than `dormant_days` |
| `NEVER_USED` | medium | Enabled, never logged on, past the grace period |
| `PWD_STALE` | medium | Password older than `password_max_age_days`, or age unknown |
| `PWD_NEVER_EXPIRES` | low | Rotation depends on a manual process |
| `WEAK_KERBEROS` | high | Has an SPN and allows RC4/DES, so its tickets can be cracked offline |
| `NAMING` | low | Name breaks the convention, so purpose can't be read from it |
| `NO_DESCRIPTION` | low | Purpose unknown |
| `EXCEPTION_EXPIRED` | medium | A risk exception lapsed |

Thresholds, privileged groups and the naming convention live in `config/policy.yaml`. Unknown keys are rejected, so a typo can't silently fall back to a default.

## Design decisions

**Read-only by design.** Disabling an account, rotating its password or removing it from a group can take down a live service. Those are production changes that need an engineer, a change record and a rollback plan. A script is the right tool for discovery, reconciliation and reporting; it is the wrong tool for acting on its own conclusions.

**Ownership before action.** The queue never recommends disabling an account before someone owns the decision. Action order is: escalate privileged or Kerberos exposure to engineering, confirm owner, disable after dependency check, schedule rotation, renew exceptions, review.

**Owner suggestions are evidence, not assignments.** Candidates come from four signals: a person named in the description, who owns the other accounts for the same application, the manager of a departed owner, and the head of the recorded department. Each carries a score and its reasons. Confidence is capped at 0.95 because inference is never certain, and anything below 0.1 is dropped as noise. An owner only changes when a person confirms it via `warden decide`.

**Messy data is reported, not hidden.** Bad rows don't crash the run. Each problem is logged with its file, row and field. Where a value can't be read, Warden assumes the riskier reading (an unreadable `enabled` flag is treated as enabled) so problems are over-reported rather than missed. UK `DD/MM/YYYY` dates are accepted, and ambiguous ones (04/03/2025) are flagged.

**Exceptions are explicit and time-limited.** Each must name the account, rule, reason, approver and expiry. Incomplete entries are rejected. Expired exceptions raise a new finding instead of quietly lapsing. Critical findings cannot be waived.

**Every conclusion is traceable.** Each scan records the SHA-256 of its inputs, so you can show exactly which data a decision was based on. The audit log is hash-chained: editing or deleting a past entry breaks the chain, and `scan` refuses to run on a log that fails verification. This makes tampering evident, not impossible; in production the log would also go to write-once storage or a SIEM.

## Optional AI triage

```bash
pip install -e ".[ai]"
export ANTHROPIC_API_KEY=...
warden scan --ai
```

For accounts with an ownership gap, an LLM suggests the account's purpose and likely team from its name, description, groups and SPNs. Guardrails:

- Output is labelled `UNVERIFIED` and goes in its own column. It never assigns an owner or changes a finding.
- No HR data or owner emails are sent to the model.
- Any failure is ignored and the scan carries on.

The point is to speed up the investigation, not to replace the person who has to sign off on it.

## What Warden deliberately doesn't do

- Disable, delete or move accounts
- Rotate passwords or change Kerberos encryption settings
- Remove group memberships
- Assign owners without confirmation
- Treat AI output as fact

## Limitations and next steps

- Input is CSV. A production version would read directly from Active Directory (`ldap3`) or Entra ID (Microsoft Graph), using a read-only service account that is itself governed.
- `lastLogonTimestamp` in AD replicates with up to a 14-day lag, so the dormancy threshold should sit well above that.
- Dependency discovery (which hosts and jobs actually use an account) would need logon event data from a SIEM.
- The queue could feed a ticketing system so each item has a tracked owner and due date.

## Layout

```
src/warden/
  models.py      data types
  loader.py      CSV loading, normalisation and data-quality issues
  policy.py      YAML policy with validation
  rules.py       governance rules
  owners.py      owner inference
  exceptions.py  risk exception register
  audit.py       hash-chained audit log
  report.py      remediation queue and outputs
  ai.py          optional AI triage
  generate.py    synthetic data
  cli.py         command line
tests/           pytest suite, including an end-to-end run of the CLI
```

Built with AI-assisted coding. I reviewed and tested the code myself.
All data is synthetic. Names, emails and domains are fictional.
