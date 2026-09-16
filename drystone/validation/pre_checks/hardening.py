# ruff: noqa
"""Hardening deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# HARDENING PRE-CHECKS
# ============================================================================


@_register("hardening")
def check_hrd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config should be enabled."""
    config_recorders = evidence.get("config-recorders", {})
    recorders = (
        config_recorders.get("ConfigurationRecorders", [])
        if isinstance(config_recorders, dict)
        else []
    )
    if len(recorders) > 0:
        return PreCheckResult("HRD-001", "PASS", f"Config enabled ({len(recorders)} recorders)", [])
    return PreCheckResult("HRD-001", "FAIL", "ConfigurationRecorders=[]", [])


@_register("hardening")
def check_hrd_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict):
        hub_status = {}
    hub_arn = hub_status.get("HubArn")
    if hub_arn:
        return PreCheckResult("HRD-002", "PASS", f"HubArn={hub_arn}", [])
    return PreCheckResult("HRD-002", "FAIL", "HubArn is empty/missing", [])


@_register("hardening")
def check_hrd_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should have standards enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-003", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-003", "SKIP", "no standards evidence", [])

    ready = 0
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        status = str(std.get("Status") or "").upper()
        controls = std.get("ControlsSummary") or {}
        enabled_controls = int(controls.get("enabled", 0)) if isinstance(controls, dict) else 0
        if status in {"READY", "ENABLED"} or enabled_controls > 0:
            ready += 1

    if ready > 0:
        return PreCheckResult("HRD-003", "PASS", f"{ready} standards enabled/ready", [])
    return PreCheckResult("HRD-003", "FAIL", "0 standards enabled", [])


@_register("hardening")
def check_hrd_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be >= 50%."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-004", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if score >= 50.0:
        return PreCheckResult("HRD-004", "PASS", f"compliance_score={score:.1f}%", [])
    return PreCheckResult(
        "HRD-004",
        "FAIL",
        f"compliance_score={score:.1f}% (<50%)",
        [],
        metadata={
            "count": failed,
            "compliance_score": round(score, 1),
            "passed": passed,
            "failed": failed,
            "warning": warning,
        },
    )


@_register("hardening")
def check_hrd_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    critical = sev_counts.get("CRITICAL", 0)
    if critical <= 0:
        return PreCheckResult("HRD-005", "PASS", f"CRITICAL count={critical}", [])
    samples = _hardening_finding_samples(evidence, "CRITICAL")
    affected = _hardening_sample_resource_ids(samples)
    return PreCheckResult(
        "HRD-005",
        "FAIL",
        f"{critical} CRITICAL Security Hub finding(s)",
        affected,
        metadata={"count": critical, "severity": "CRITICAL", "sample_findings": samples},
    )


@_register("hardening")
def check_hrd_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config recorder should be recording with delivery channel."""
    config_recorders = evidence.get("config-recorders", {})
    if not isinstance(config_recorders, dict):
        config_recorders = {}
    recorders = config_recorders.get("ConfigurationRecorders", [])
    if not isinstance(recorders, list) or len(recorders) == 0:
        return PreCheckResult("HRD-006", "SKIP", "Config not enabled (HRD-001 applies)", [])

    recorder_status_doc = evidence.get("config-recorder-status", {})
    status_items = (
        recorder_status_doc.get("ConfigurationRecordersStatus", [])
        if isinstance(recorder_status_doc, dict)
        else []
    )

    recording_ok = False
    if isinstance(status_items, list):
        for s in status_items:
            if isinstance(s, dict) and s.get("recording") is True:
                recording_ok = True
                break

    channels_doc = evidence.get("config-delivery-channels", {})
    channels = channels_doc.get("DeliveryChannels", []) if isinstance(channels_doc, dict) else []
    channel_ok = False
    if isinstance(channels, list):
        for c in channels:
            if isinstance(c, dict) and c.get("s3BucketName"):
                channel_ok = True
                break

    if recording_ok and channel_ok:
        return PreCheckResult("HRD-006", "PASS", "recorder active, delivery channel configured", [])
    issues = []
    if not recording_ok:
        issues.append("recording=false")
    if not channel_ok:
        issues.append("no delivery channel")
    return PreCheckResult("HRD-006", "FAIL", "; ".join(issues), [])


@_register("hardening")
def check_hrd_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """High severity Security Hub findings should be <= 10."""
    sev_counts, _ = _get_hardening_counts(evidence)
    high = sev_counts.get("HIGH", 0)
    if high <= 10:
        return PreCheckResult("HRD-009", "PASS", f"HIGH count={high} (<=10)", [])
    samples = _hardening_finding_samples(evidence, "HIGH")
    affected = _hardening_sample_resource_ids(samples)
    return PreCheckResult(
        "HRD-009",
        "FAIL",
        f"{high} HIGH Security Hub finding(s) (>10)",
        affected,
        metadata={"count": high, "severity": "HIGH", "sample_findings": samples},
    )


@_register("hardening")
def check_hrd_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """Medium severity Security Hub findings should be <= 20."""
    sev_counts, _ = _get_hardening_counts(evidence)
    medium = sev_counts.get("MEDIUM", 0)
    if medium <= 20:
        return PreCheckResult("HRD-012", "PASS", f"MEDIUM count={medium} (<=20)", [])
    samples = _hardening_finding_samples(evidence, "MEDIUM")
    affected = _hardening_sample_resource_ids(samples)
    return PreCheckResult(
        "HRD-012",
        "FAIL",
        f"{medium} MEDIUM Security Hub finding(s) (>20)",
        affected,
        metadata={"count": medium, "severity": "MEDIUM", "sample_findings": samples},
    )


@_register("hardening")
def check_hrd_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """Outdated Security Hub standards should be updated."""
    # SKIP when evidence key is entirely missing (cannot evaluate)
    if "security-hub-enabled-standards" not in evidence:
        return PreCheckResult("HRD-013", "SKIP", "no standards evidence", [])

    enabled_standards = evidence["security-hub-enabled-standards"]
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-013", "SKIP", "unexpected standards format", [])

    # ARNs use slash-separated versions: ".../benchmark/v/1.2.0"
    # Use path fragments (with leading slash) — "v1.2.0" would NOT match "v/1.2.0".
    outdated_fragments = ["/1.2.0", "/1.3.0", "/2016", "/2017"]
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        for fragment in outdated_fragments:
            if fragment in arn:
                return PreCheckResult("HRD-013", "FAIL", f"outdated standard: {arn}", [])

    return PreCheckResult("HRD-013", "PASS", "no outdated standards", [])


@_register("hardening")
def check_hrd_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """GuardDuty should be enabled."""
    gd_detectors = evidence.get("guardduty-detectors", [])
    if isinstance(gd_detectors, list) and len(gd_detectors) > 0:
        return PreCheckResult("HRD-014", "PASS", f"{len(gd_detectors)} detectors", [])
    # Also check dict shape
    if isinstance(gd_detectors, dict) and gd_detectors.get("DetectorIds"):
        ids = gd_detectors["DetectorIds"]
        if isinstance(ids, list) and len(ids) > 0:
            return PreCheckResult("HRD-014", "PASS", f"{len(ids)} detectors", [])
    return PreCheckResult(
        "HRD-014",
        "FAIL",
        "no GuardDuty detectors",
        ["AWS::::Account"],
        metadata={"count": 0, "service": "GuardDuty", "enabled": False},
    )


@_register("hardening")
def check_hrd_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Low severity Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    low = sev_counts.get("LOW", 0)
    if low <= 0:
        return PreCheckResult("HRD-016", "PASS", f"LOW count={low}", [])
    return PreCheckResult("HRD-016", "FAIL", f"LOW count={low} (>0)", [])


@_register("hardening")
def check_hrd_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub PCI DSS standard should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-007", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-007", "SKIP", "no standards evidence", [])

    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        status = str(std.get("Status") or "").upper()
        if "pci-dss" in arn.lower() and status in {"READY", "ENABLED"}:
            return PreCheckResult("HRD-007", "PASS", f"PCI DSS standard enabled: {arn}", [])

    return PreCheckResult("HRD-007", "FAIL", "no PCI DSS standard enabled", [])


@_register("hardening")
def check_hrd_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 50-70% range (medium risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-008", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 50.0 <= score < 70.0:
        return PreCheckResult("HRD-008", "FAIL", f"compliance_score={score:.1f}% (50-70%)", [])
    return PreCheckResult(
        "HRD-008", "PASS", f"compliance_score={score:.1f}% (not in 50-70% band)", []
    )


@_register("hardening")
def check_hrd_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """No conformance packs configured."""
    packs = evidence.get("config-conformance-packs", None)
    if packs is None:
        return PreCheckResult("HRD-010", "SKIP", "no conformance-packs evidence", [])
    if not isinstance(packs, list):
        return PreCheckResult("HRD-010", "SKIP", "unexpected conformance-packs format", [])
    if len(packs) == 0:
        return PreCheckResult(
            "HRD-010",
            "FAIL",
            "0 conformance packs configured",
            [],
            metadata={"count": 0, "conformance_pack_count": 0},
        )
    return PreCheckResult("HRD-010", "PASS", f"{len(packs)} conformance pack(s) configured", [])


@_register("hardening")
def check_hrd_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 70-85% range (acceptable risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-011", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 70.0 <= score < 85.0:
        return PreCheckResult("HRD-011", "FAIL", f"compliance_score={score:.1f}% (70-85%)", [])
    return PreCheckResult(
        "HRD-011", "PASS", f"compliance_score={score:.1f}% (not in 70-85% band)", []
    )


@_register("hardening")
def check_hrd_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 85-95% range (low risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-015", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 85.0 <= score < 95.0:
        return PreCheckResult("HRD-015", "FAIL", f"compliance_score={score:.1f}% (85-95%)", [])
    return PreCheckResult(
        "HRD-015", "PASS", f"compliance_score={score:.1f}% (not in 85-95% band)", []
    )


def _get_hardening_counts(evidence: Dict[str, Any]):
    """Return (severity_counts, compliance_counts) from hardening evidence."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
    comp_counts = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "NOT_AVAILABLE": 0, "OTHER": 0}

    summary = evidence.get("security-hub-findings-summary")
    if isinstance(summary, dict):
        sc = summary.get("severity_counts")
        if isinstance(sc, dict):
            for k in sev_counts:
                sev_counts[k] = int(sc.get(k, 0) or 0)
        cc = summary.get("compliance_status_counts")
        if isinstance(cc, dict):
            for k in comp_counts:
                comp_counts[k] = int(cc.get(k, 0) or 0)

    # Fallback: derive from raw findings
    if sum(sev_counts.values()) == 0:
        findings = evidence.get("security-hub-findings")
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = str(((f.get("Severity") or {}).get("Label") or "")).upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                comp = str(((f.get("Compliance") or {}).get("Status") or "")).upper()
                if comp in comp_counts:
                    comp_counts[comp] += 1

    return sev_counts, comp_counts


def _hardening_finding_samples(
    evidence: Dict[str, Any],
    severity: str,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Return compact Security Hub finding samples for a severity bucket."""
    findings = evidence.get("security-hub-findings")
    if not isinstance(findings, list):
        return []

    out: List[Dict[str, Any]] = []
    target = str(severity).upper()
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        sev = str(((finding.get("Severity") or {}).get("Label") or "")).upper()
        if sev != target:
            continue
        out.append(
            {
                "index": idx,
                "id": finding.get("Id"),
                "title": finding.get("Title"),
                "severity": sev,
                "compliance_status": (finding.get("Compliance") or {}).get("Status"),
                "record_state": finding.get("RecordState"),
                "workflow_status": (finding.get("Workflow") or {}).get("Status"),
                "resource_ids": [
                    r.get("Id")
                    for r in (finding.get("Resources") or [])
                    if isinstance(r, dict) and r.get("Id")
                ],
            }
        )
        if len(out) >= limit:
            break
    return out


def _hardening_sample_resource_ids(samples: List[Dict[str, Any]]) -> List[str]:
    """Flatten resource IDs from compact Security Hub samples."""
    out: List[str] = []
    for sample in samples:
        for resource_id in sample.get("resource_ids") or []:
            if resource_id and str(resource_id) not in out:
                out.append(str(resource_id))
    return out[:10]


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
