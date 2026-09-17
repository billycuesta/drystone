#!/usr/bin/env python3
"""Cross-validate Drystone's deterministic AWS checks against Prowler's catalog.

Roadmap: P1.11a in PLAN_PROFESSIONAL_GRADE_ROADMAP.md -- a cheap, read-only
comparison to find coverage gaps in either direction before deciding whether
to delegate any commodity checks to Prowler (P1.11b). No runtime dependency
is added to the audit path: this script fetches Prowler's public check
catalog and CIS AWS Foundations compliance mapping straight from its GitHub
repo (no `prowler-cloud` pip install, no AWS credentials, no test account).

The comparison is anchored on `cis_id`, a field every Drystone checklist item
already carries -- Prowler publishes an official CIS-control-to-check-id
mapping, so matches here are verified, not keyword-guessed.

Usage:
    python scripts/prowler_gap_analysis.py [--cis-version 1.5] [--output PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

REPO = "prowler-cloud/prowler"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/master?recursive=1"
CIS_URL_TEMPLATE = (
    f"https://raw.githubusercontent.com/{REPO}/master/prowler/compliance/aws/cis_{{version}}_aws.json"
)
USER_AGENT = "drystone-prowler-gap-analysis"
AWS_SERVICES_PREFIX = "prowler/providers/aws/services/"

# Drystone skills that map reasonably cleanly onto one (or a couple of)
# Prowler service folder(s). Skills left out (exposure, network, hardening,
# alerting, vulns, compute, messaging, cicd, recon, sistemas_explotables_red)
# span too many AWS services in Prowler to make a single-row count meaningful.
SKILL_TO_PROWLER_SERVICES = {
    "iam": ["iam"],
    "kms": ["kms"],
    "ecr": ["ecr"],
    "secretsmanager": ["secretsmanager"],
    "cloudtrail_events": ["cloudtrail"],
    "waf": ["waf", "wafv2"],
}


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def fetch_prowler_aws_checks() -> List[Dict[str, str]]:
    """Return [{"service": ..., "check_id": ...}, ...] for every AWS check in Prowler."""
    tree = _fetch_json(TREE_URL)
    checks = []
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if not (path.startswith(AWS_SERVICES_PREFIX) and path.endswith(".metadata.json")):
            continue
        rel = path[len(AWS_SERVICES_PREFIX) :]
        parts = rel.split("/")
        if len(parts) < 2:
            continue
        service = parts[0]
        check_id = parts[-1][: -len(".metadata.json")]
        checks.append({"service": service, "check_id": check_id})
    return checks


def fetch_cis_mapping(version: str) -> Dict[str, List[str]]:
    """Return {cis_id: [prowler_check_id, ...]} for a Prowler CIS AWS Foundations version."""
    data = _fetch_json(CIS_URL_TEMPLATE.format(version=version))
    mapping: Dict[str, List[str]] = {}
    for requirement in data.get("Requirements", []):
        cis_id = requirement.get("Id")
        if cis_id:
            mapping[cis_id] = list(requirement.get("Checks") or [])
    return mapping


def load_drystone_checklists(skills_dir: Path) -> List[Dict[str, Optional[str]]]:
    """Return a flat [{"skill", "id", "cis_id", "title"}, ...] across every checklist.json."""
    items: List[Dict[str, Optional[str]]] = []
    for checklist_path in sorted(skills_dir.glob("*/checklist.json")):
        skill = checklist_path.parent.name
        try:
            data = json.loads(checklist_path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"  warning: could not read {checklist_path}: {e}", file=sys.stderr)
            continue
        for item in data.get("items", []):
            cis_id = item.get("cis_id")
            # Some checklists spell "no CIS control" as the literal string
            # "N/A" instead of omitting the field -- normalize both to None.
            if isinstance(cis_id, str) and cis_id.strip().upper() in {"", "N/A"}:
                cis_id = None
            items.append(
                {
                    "skill": skill,
                    "id": item.get("id", ""),
                    "cis_id": cis_id,
                    "title": item.get("title", ""),
                }
            )
    return items


def _cis_sort_key(cis_id: str) -> tuple:
    return tuple(int(part) if part.isdigit() else part for part in cis_id.split("."))


def build_gap_report(
    prowler_checks: List[Dict[str, str]],
    cis_mapping: Dict[str, List[str]],
    drystone_items: List[Dict[str, Optional[str]]],
    cis_version: str,
) -> str:
    lines = ["# Prowler vs. Drystone Coverage Gap Report", ""]
    lines.append(f"- Prowler AWS check catalog: {len(prowler_checks)} checks")
    lines.append(f"- Prowler CIS AWS Foundations v{cis_version}: {len(cis_mapping)} controls")
    lines.append(f"- Drystone checklist items (all skills): {len(drystone_items)}")
    lines.append("")

    # 1. Drystone items with a cis_id, matched against Prowler's official CIS mapping.
    matched = []
    unmatched_cis = []
    for item in drystone_items:
        cis_id = item.get("cis_id")
        if not cis_id:
            continue
        prowler_ids = cis_mapping.get(cis_id)
        if prowler_ids:
            matched.append((item, prowler_ids))
        else:
            unmatched_cis.append(item)

    lines.append(f"## 1. Drystone checks with a CIS ID, matched against Prowler v{cis_version}")
    lines.append("")
    lines.append(f"- Matched (Prowler implements the same CIS control): {len(matched)}")
    lines.append(f"- No Prowler v{cis_version} equivalent for that CIS ID: {len(unmatched_cis)}")
    lines.append("")
    if unmatched_cis:
        lines.append("| Drystone ID | Skill | CIS ID | Title |")
        lines.append("|---|---|---|---|")
        for item in unmatched_cis:
            lines.append(f"| {item['id']} | {item['skill']} | {item['cis_id']} | {item['title']} |")
        lines.append("")

    # 2. Drystone items with no cis_id at all (expected for hand-built/threat-intel checks).
    no_cis = [i for i in drystone_items if not i.get("cis_id")]
    lines.append("## 2. Drystone checks with no CIS mapping at all")
    lines.append("")
    lines.append(
        f"{len(no_cis)} checks (out of {len(drystone_items)}) carry no `cis_id` -- expected for "
        "Drystone-specific checks (CloudTrail threat-intel correlation, PCI-only controls, etc.) "
        "that fall outside CIS scope by design. Not necessarily a gap."
    )
    by_skill: Dict[str, int] = {}
    for item in no_cis:
        skill = str(item["skill"])
        by_skill[skill] = by_skill.get(skill, 0) + 1
    if by_skill:
        lines.append("")
        lines.append("| Skill | Non-CIS-mapped checks |")
        lines.append("|---|---|")
        for skill, count in sorted(by_skill.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {skill} | {count} |")
    lines.append("")

    # 3. CIS controls Prowler covers that Drystone has no checklist item for at all.
    drystone_cis_ids = {item["cis_id"] for item in drystone_items if item.get("cis_id")}
    missing_in_drystone = sorted(set(cis_mapping) - drystone_cis_ids, key=_cis_sort_key)
    lines.append(f"## 3. CIS v{cis_version} controls Prowler covers that Drystone has no check for")
    lines.append("")
    lines.append(f"{len(missing_in_drystone)} CIS controls out of {len(cis_mapping)}.")
    lines.append("")
    if missing_in_drystone:
        lines.append("| CIS ID | Prowler check(s) |")
        lines.append("|---|---|")
        for cis_id in missing_in_drystone:
            lines.append(f"| {cis_id} | {', '.join(cis_mapping[cis_id])} |")
        lines.append("")

    # 4. Coarse per-service check-count comparison, informational only.
    lines.append("## 4. Coarse check-count comparison (informational, not a gap list)")
    lines.append("")
    lines.append(
        "Most Drystone skills span several Prowler service folders (e.g. `exposure` spans "
        "s3/rds/elasticsearch/...), so only skills that map onto one or two Prowler services "
        "are shown here. Higher Prowler counts are expected -- Prowler covers each service far "
        "more exhaustively; this table is directional, not a 1:1 gap list."
    )
    prowler_by_service: Dict[str, int] = {}
    for check in prowler_checks:
        prowler_by_service[check["service"]] = prowler_by_service.get(check["service"], 0) + 1
    drystone_counts: Dict[str, int] = {}
    for item in drystone_items:
        skill = str(item["skill"])
        drystone_counts[skill] = drystone_counts.get(skill, 0) + 1
    lines.append("")
    lines.append("| Drystone skill | Drystone checks | Prowler service(s) | Prowler checks |")
    lines.append("|---|---|---|---|")
    for skill, services in sorted(SKILL_TO_PROWLER_SERVICES.items()):
        prowler_count = sum(prowler_by_service.get(s, 0) for s in services)
        lines.append(
            f"| {skill} | {drystone_counts.get(skill, 0)} | {', '.join(services)} | {prowler_count} |"
        )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--cis-version",
        default="1.5",
        help="Prowler CIS AWS Foundations version to compare against "
        "(default: 1.5, matching Drystone's IAM checklist framework)",
    )
    parser.add_argument(
        "--output", type=Path, default=None, help="Write the report to this path instead of stdout"
    )
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "drystone" / "skills",
        help="Directory containing per-skill checklist.json files",
    )
    args = parser.parse_args()

    try:
        print("Fetching Prowler AWS check catalog from GitHub...", file=sys.stderr)
        prowler_checks = fetch_prowler_aws_checks()
        print(f"  {len(prowler_checks)} checks found", file=sys.stderr)

        print(f"Fetching Prowler CIS AWS Foundations v{args.cis_version} mapping...", file=sys.stderr)
        cis_mapping = fetch_cis_mapping(args.cis_version)
        print(f"  {len(cis_mapping)} CIS controls mapped", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"error: could not reach GitHub ({e}). This script needs network access.", file=sys.stderr)
        return 1

    print("Loading Drystone checklists...", file=sys.stderr)
    drystone_items = load_drystone_checklists(args.skills_dir)
    print(f"  {len(drystone_items)} checklist items loaded", file=sys.stderr)

    report = build_gap_report(prowler_checks, cis_mapping, drystone_items, args.cis_version)

    if args.output:
        args.output.write_text(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
