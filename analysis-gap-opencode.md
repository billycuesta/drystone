# Analysis GAPs - OpenCode

Date: 2026-02-16  
Scope reviewed:
- `/Users/gcuesta/Projects/drystone/audit-logs/net-qa-1_2026-02-16T12-23-53`
- `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16`
- `/Users/gcuesta/Projects/drystone/audit-logs/exp-qa-1_2026-02-15T19-14-05`

## Executive Summary

Main inconsistencies detected:
- IAM evidence references are not resolvable in the persisted evidence layout.
- IAM findings metadata is degraded (`skill=aggregated`, `evidence_count=0`, `checklist_version=N/A`).
- Exposure finding `EXP-015` has inconsistent `affected_resources` vs cross-account principal found in evidence.
- Network PDF pagination shows blank/orphan pages due to page-break behavior with large evidence blocks.
- Markdown/PDF are not fully aligned in findings summary behavior (Top 10 vs all findings).

## 1) IAM - Invalid evidence references (High)

### Finding
In `iam.json`, all findings include `evidence_refs` that do not consistently resolve to actual evidence objects.

### Evidence
- Findings file:
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/findings/iam.json`
- Evidence files use list-based structures for key datasets:
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/evidence/iam/users.json`
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/evidence/iam/roles.json`
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/evidence/iam/policies.json`
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/evidence/iam/groups.json`
- Credential report evidence is CSV, but refs point to logical keys:
  - `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/evidence/iam/credential-report.csv`

### Examples
- `IAM-004`: `credential-report#a2secure` (real file is `credential-report.csv`).
- `IAM-002`: `users.json#a2secure` (users file is a list, not dict keyed by username).
- `IAM-017`: `roles.json#AWSCloudFormationStackSetExecutionRole` (roles file is list, not dict keyed by role name).

### Impact
- Weak audit traceability and difficult automatic validation.
- Gaps between finding references and persisted evidence model.

### Recommendation
- Normalize IAM evidence into indexed maps (`by_name`, `by_id`) like exposure/network.
- Standardize ref syntax across skills (single resolvable convention).
- Add explicit CSV reference support or transform credential report to indexed JSON before analysis.

## 2) IAM - Findings metadata inconsistency (High)

### Finding
IAM findings metadata does not reflect a pure IAM run context.

### Evidence
- `/Users/gcuesta/Projects/drystone/audit-logs/iam-qa-1_2026-02-15T19-02-16/findings/iam.json`
  - `skill: "aggregated"`
  - `evidence_count: 0`
  - `checklist_version: "N/A"`

### Impact
- Scope ambiguity in final reports.
- Reliability issues for metrics/history dashboards.

### Recommendation
- Persist and propagate real execution skill in findings payload.
- Recalculate `evidence_count` from stored evidence artifacts.
- Enforce checklist version propagation from active checklist.

## 3) Exposure - `EXP-015` affected resource mismatch (High)

### Finding
`affected_resources` in `EXP-015` includes local account root instead of the cross-account principal seen in evidence.

### Evidence
- Finding file:
  - `/Users/gcuesta/Projects/drystone/audit-logs/exp-qa-1_2026-02-15T19-14-05/findings/exposure.json`
- Cross-account principal in snippet:
  - `arn:aws:iam::127311923021:root`
- Reported affected principal:
  - `arn:aws:iam::032014372957:root`
- Source policy evidence:
  - `/Users/gcuesta/Projects/drystone/audit-logs/exp-qa-1_2026-02-15T19-14-05/evidence/exposure/s3-buckets.json`

### Impact
- Misleading remediation target.
- Potentially incorrect ownership/escalation path reporting.

### Recommendation
- Build `affected_resources` from extracted principals in policy statements when present.
- Add consistency validator: principals in snippet must be reflected in `affected_resources`.

## 4) Network PDF - blank/orphan pages (Medium)

### Finding
Network PDF has blank/orphan pages around severity section transitions.

### Evidence
- PDF:
  - `/Users/gcuesta/Projects/drystone/audit-logs/net-qa-1_2026-02-16T12-23-53/reports/audit-report-network.pdf`
- MD equivalent does not show this issue:
  - `/Users/gcuesta/Projects/drystone/audit-logs/net-qa-1_2026-02-16T12-23-53/reports/audit-report-network.md`

### Cause
Interplay of forced page breaks + `page-break-inside` behavior with long evidence blocks.

### Recommendation
- Define one pagination policy (per section or per finding) and keep it consistent.
- Allow controlled splits for evidence code blocks while protecting headings/cards from orphan layouts.

## 5) MD/PDF summary parity drift (Medium)

### Finding
Behavior drift exists between formats in findings summary section.

### Evidence
- Markdown still presents Top 10 wording/logic in some generated reports.
- PDF has been iterated to show full findings table.

### Impact
- Different report contents depending on output format.

### Recommendation
- Unify product rule: either Top N or All findings, configurable and shared by all formatters.

## Positive consistency checks

- `network.json` and `exposure.json` have coherent summary metadata.
- Exposure `EXP-013` appears evidence-supported for target bucket (`tulotero-pci-prod-logs-backup`) lacking explicit TLS deny statement.

## Suggested priority for Claude remediation

- `P0`:
  - Fix IAM evidence reference model and syntax.
  - Fix `EXP-015` `affected_resources` mapping.
  - Fix IAM findings metadata propagation.
- `P1`:
  - Stabilize PDF pagination policy for long evidence sections.
  - Align summary behavior across MD/PDF.
- `P2`:
  - Add cross-artifact consistency tests (`evidence_refs`, affected principals, formatter parity).
