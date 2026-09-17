#!/usr/bin/env python3
"""Generate PRE_CHECK_IMPACTS entries for checks missing impact text.

Usage:
    source drystone_env/bin/activate
    python scripts/generate_impacts.py [--dry-run] [--limit N] > /tmp/new_impacts.py

Options:
    --dry-run   Print the list of missing IDs without calling Claude API
    --limit N   Process at most N checks (default: all)
"""
# ruff: noqa: E402,I001
import argparse
import sys

sys.path.insert(0, ".")

from drystone.validation.pre_checks import (
    PRE_CHECK_DESCRIPTIONS,
    PRE_CHECK_IMPACTS,
    PRE_CHECK_REMEDIATIONS,
    PRE_CHECK_REGISTRY,
)

PROMPT_TEMPLATE = """\
You are a cloud security QSA writing a concise impact statement for an AWS security finding.

Check ID: {check_id}
Description: {description}
Remediation: {remediation}

Write a PRE_CHECK_IMPACTS entry: exactly 2 paragraphs separated by a blank line.
Paragraph 1 — Attacker scenario: concrete attack path if this check fails (name the AWS service/resource).
Paragraph 2 — Business/compliance consequence: data exposure, compliance violation (reference PCI DSS control if relevant).

Rules:
- 3-5 sentences total
- No bullet points
- Start paragraph 1 with "An attacker who..." or "If [condition], an attacker..."
- Start paragraph 2 with "From a compliance perspective..." or "In a PCI DSS context..."
- Do NOT mention the check ID
- Return ONLY the impact text, nothing else — no Python formatting, no quotes
"""


def _get_registered_ids() -> set[str]:
    ids = set()
    for skill_checks in PRE_CHECK_REGISTRY.values():
        for fn in skill_checks:
            raw = fn.__name__
            if raw.startswith("check_"):
                raw = raw[len("check_"):]
            check_id = raw.replace("_", "-").upper()
            ids.add(check_id)
    return ids


def _to_python_string(text: str) -> str:
    lines = text.strip().split("\n\n")
    parts = []
    for i, para in enumerate(lines):
        para = para.strip().replace("\\", "\\\\").replace('"', '\\"')
        sep = "\\n\\n" if i < len(lines) - 1 else ""
        parts.append(f'        "{para}{sep}"')
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    all_ids = _get_registered_ids()
    missing = sorted(cid for cid in all_ids if cid not in PRE_CHECK_IMPACTS)

    print(f"# Total registered checks: {len(all_ids)}", file=sys.stderr)
    print(f"# Already have impact text: {len(PRE_CHECK_IMPACTS)}", file=sys.stderr)
    print(f"# Missing impact text:      {len(missing)}", file=sys.stderr)

    if args.dry_run:
        print("\n".join(missing))
        return

    if args.limit:
        missing = missing[: args.limit]
        print(f"# Processing {len(missing)} (limited)", file=sys.stderr)

    try:
        from anthropic import Anthropic
    except ImportError:
        print("ERROR: anthropic package not installed. Run: pip install anthropic", file=sys.stderr)
        sys.exit(1)

    client = Anthropic()
    results: dict[str, str] = {}
    skipped = []

    for i, check_id in enumerate(missing, 1):
        desc = PRE_CHECK_DESCRIPTIONS.get(check_id, "")
        remed = PRE_CHECK_REMEDIATIONS.get(check_id, "")
        if not desc and not remed:
            skipped.append(check_id)
            print(f"  [{i}/{len(missing)}] SKIP {check_id} (no description/remediation)", file=sys.stderr)
            continue

        print(f"  [{i}/{len(missing)}] {check_id} ...", end="", file=sys.stderr, flush=True)
        try:
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                messages=[{
                    "role": "user",
                    "content": PROMPT_TEMPLATE.format(
                        check_id=check_id,
                        description=desc[:600],
                        remediation=remed[:400],
                    ),
                }],
            )
            impact_text = resp.content[0].text.strip()
            results[check_id] = impact_text
            print(" OK", file=sys.stderr)
        except Exception as e:
            print(f" ERROR: {e}", file=sys.stderr)

    if skipped:
        print(f"\n# Skipped (no description+remediation): {', '.join(skipped)}", file=sys.stderr)

    print("\n# ── Add these entries to PRE_CHECK_IMPACTS in pre_checks.py ──────────────")
    print("# Paste inside the PRE_CHECK_IMPACTS dict:\n")
    for check_id in sorted(results):
        text_py = _to_python_string(results[check_id])
        print(f'    "{check_id}": (')
        print(text_py)
        print("    ),")


if __name__ == "__main__":
    main()
