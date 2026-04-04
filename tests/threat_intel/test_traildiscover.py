"""Tests for drystone.threat_intel.traildiscover module."""

import pytest
from unittest.mock import patch

from drystone.threat_intel.traildiscover import (
    _load_catalog,
    enrich_finding,
    get_event_context,
    get_incidents,
    get_mitre_context,
    is_used_in_wild,
)


class TestLoadCatalog:
    def test_catalog_loads_as_dict(self):
        catalog = _load_catalog()
        assert isinstance(catalog, dict)
        assert len(catalog) > 100

    def test_catalog_indexed_by_event_name(self):
        catalog = _load_catalog()
        assert "DeleteTrail" in catalog
        assert "ConsoleLogin" in catalog

    def test_catalog_lru_cached(self):
        # Calling twice returns same object (cached)
        c1 = _load_catalog()
        c2 = _load_catalog()
        assert c1 is c2


class TestGetEventContext:
    def test_known_event_returns_dict(self):
        ctx = get_event_context("DeleteTrail")
        assert ctx is not None
        assert isinstance(ctx, dict)
        assert ctx.get("eventName") == "DeleteTrail"

    def test_unknown_event_returns_none(self):
        assert get_event_context("NonExistentEvent_XYZ_99999") is None

    def test_known_event_has_mitre_fields(self):
        ctx = get_event_context("DeleteTrail")
        assert "mitreAttackTactics" in ctx
        assert len(ctx["mitreAttackTactics"]) > 0

    def test_known_event_has_used_in_wild(self):
        ctx = get_event_context("DeleteTrail")
        assert "usedInWild" in ctx


class TestIsUsedInWild:
    def test_deletetrail_is_wild(self):
        assert is_used_in_wild("DeleteTrail") is True

    def test_unknown_event_not_wild(self):
        assert is_used_in_wild("NonExistentEvent_XYZ_99999") is False

    def test_returns_bool(self):
        result = is_used_in_wild("DeleteTrail")
        assert isinstance(result, bool)


class TestGetMitreContext:
    def test_deletetrail_has_tactics(self):
        ctx = get_mitre_context("DeleteTrail")
        assert "tactics" in ctx
        assert len(ctx["tactics"]) > 0

    def test_result_has_required_keys(self):
        ctx = get_mitre_context("DeleteTrail")
        assert set(ctx.keys()) >= {"tactics", "techniques", "sub_techniques"}

    def test_unknown_event_returns_empty_dict(self):
        ctx = get_mitre_context("NonExistentEvent_XYZ_99999")
        assert ctx == {}

    def test_tactics_contain_mitre_format(self):
        ctx = get_mitre_context("DeleteTrail")
        # Each tactic should look like "TA0005 - Defense Evasion"
        for tactic in ctx["tactics"]:
            assert "TA" in tactic


class TestGetIncidents:
    def test_deletetrail_has_incidents(self):
        incidents = get_incidents("DeleteTrail")
        assert isinstance(incidents, list)
        assert len(incidents) > 0

    def test_incidents_have_description_key(self):
        incidents = get_incidents("DeleteTrail")
        for inc in incidents:
            assert "description" in inc

    def test_unknown_event_returns_empty_list(self):
        assert get_incidents("NonExistentEvent_XYZ_99999") == []


class TestEnrichFinding:
    def test_fail_finding_gets_threat_intel(self):
        finding = {"id": "CTEF-003", "severity": "Critical", "title": "Tampering"}
        enrich_finding(finding, ["DeleteTrail", "StopLogging"])
        assert "threat_intel" in finding

    def test_threat_intel_has_required_fields(self):
        finding = {"id": "CTEF-003", "severity": "Critical"}
        enrich_finding(finding, ["DeleteTrail"])
        ti = finding["threat_intel"]
        assert "mitre_tactics" in ti
        assert "mitre_techniques" in ti
        assert "used_in_wild" in ti
        assert "real_incidents" in ti

    def test_used_in_wild_is_true_for_deletetrail(self):
        finding = {"id": "CTEF-003", "severity": "Critical"}
        enrich_finding(finding, ["DeleteTrail"])
        assert finding["threat_intel"]["used_in_wild"] is True

    def test_unknown_event_produces_no_threat_intel(self):
        finding = {"id": "CTEF-999", "severity": "High"}
        enrich_finding(finding, ["NonExistentEvent_XYZ_99999"])
        assert "threat_intel" not in finding

    def test_empty_event_names_no_threat_intel(self):
        finding = {"id": "CTEF-005", "severity": "Medium"}
        enrich_finding(finding, [])
        assert "threat_intel" not in finding

    def test_multiple_events_merges_tactics(self):
        finding = {"id": "CTEF-004", "severity": "High"}
        enrich_finding(finding, ["CreateAccessKey", "AttachUserPolicy"])
        ti = finding["threat_intel"]
        # Should have tactics from both events, deduplicated
        assert isinstance(ti["mitre_tactics"], list)
        assert len(ti["mitre_tactics"]) >= 1

    def test_real_incidents_are_strings(self):
        finding = {"id": "CTEF-003", "severity": "Critical"}
        enrich_finding(finding, ["DeleteTrail"])
        incidents = finding["threat_intel"]["real_incidents"]
        assert all(isinstance(i, str) for i in incidents)

    def test_finding_not_mutated_if_no_context(self):
        finding = {"id": "CTEF-005", "severity": "Medium", "title": "Throttling"}
        original_keys = set(finding.keys())
        enrich_finding(finding, [])
        assert set(finding.keys()) == original_keys
