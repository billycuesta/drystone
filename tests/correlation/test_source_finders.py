"""Tests for orphan pattern source finders (Fix 3)."""

from drystone.correlation.patterns import (
    PATTERN_REGISTRY,
    _find_sources_lambda_env_secret_leakage,
    _find_sources_nat_egress_pivoting,
    _find_sources_wildcard_principal,
)
from drystone.models.findings import Finding


def _finding(id, title, severity="High"):
    return Finding(
        id=id,
        severity=severity,
        risk_score=7.0,
        title=title,
        description=f"Desc {id}",
        remediation=f"Fix {id}",
    )


class TestSourceFinderLambdaEnv:
    def test_matches_vulns_lambda_findings(self):
        findings_by_skill = {
            "vulns": [
                _finding("VULN-010", "Lambda env vars contain secret keys"),
                _finding("VULN-001", "Unrelated CVE"),
            ],
        }
        result = _find_sources_lambda_env_secret_leakage(findings_by_skill, {}, {})
        assert len(result) == 1
        assert result[0].id == "VULN-010"

    def test_matches_secretsmanager_rotation(self):
        findings_by_skill = {
            "vulns": [],
            "secretsmanager": [
                _finding("SM-001", "Lambda rotation function misconfigured"),
            ],
        }
        result = _find_sources_lambda_env_secret_leakage(findings_by_skill, {}, {})
        assert len(result) == 1


class TestSourceFinderWildcardPrincipal:
    def test_matches_iam_wildcard(self):
        findings_by_skill = {
            "iam": [
                _finding("IAM-030", "Cross-account trust without ExternalId"),
                _finding("IAM-001", "Root MFA disabled"),
            ],
        }
        result = _find_sources_wildcard_principal(findings_by_skill, {}, {})
        assert len(result) == 1
        assert result[0].id == "IAM-030"

    def test_matches_exposure_wildcard(self):
        findings_by_skill = {
            "iam": [],
            "exposure": [
                _finding("EXP-023", "Wildcard principal in S3 bucket policy"),
            ],
        }
        result = _find_sources_wildcard_principal(findings_by_skill, {}, {})
        assert len(result) == 1


class TestSourceFinderNatEgress:
    def test_matches_network_nat_findings(self):
        findings_by_skill = {
            "network": [
                _finding("NET-010", "NAT gateway without egress filtering"),
                _finding("NET-001", "Security group allows all inbound"),
            ],
        }
        result = _find_sources_nat_egress_pivoting(findings_by_skill, {}, {})
        assert len(result) == 1
        assert result[0].id == "NET-010"


class TestPatternRegistryHasSourceFinders:
    """Verify the 3 previously-orphan patterns now have source_finder."""

    def test_lambda_env_has_source_finder(self):
        p = PATTERN_REGISTRY.get("vulns_lambda_env_secret_leakage")
        assert p is not None
        assert p.source_finder is not None

    def test_wildcard_principal_has_source_finder(self):
        p = PATTERN_REGISTRY.get("iam_resource_policy_wildcard_principal")
        assert p is not None
        assert p.source_finder is not None

    def test_nat_egress_has_source_finder(self):
        p = PATTERN_REGISTRY.get("network_nat_egress_pivoting")
        assert p is not None
        assert p.source_finder is not None
