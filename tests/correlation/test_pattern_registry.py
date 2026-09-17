"""Tests for PatternRegistry (rec AN: duplicate pattern IDs must not silently overwrite)."""

import pytest

from drystone.correlation.models import ExploitabilityInfo, ThreatContext
from drystone.correlation.patterns import DynamicCorrelationPattern, PatternRegistry


def _make_pattern(pattern_id: str, name: str = "test pattern") -> DynamicCorrelationPattern:
    return DynamicCorrelationPattern(
        id=pattern_id,
        name=name,
        description="test",
        severity="High",
        skills_required=["iam"],
        matcher=lambda findings, evidence, ctx: False,
        attack_path_generator=lambda ctx: [],
        remediation_generator=lambda ctx: [],
        threat_context=ThreatContext(),
        exploitability=ExploitabilityInfo(),
    )


class TestPatternRegistryRegister:
    def test_registers_a_new_pattern(self):
        registry = PatternRegistry()
        registry.register(_make_pattern("PAT-001"))
        assert registry.get("PAT-001") is not None

    def test_duplicate_id_raises_instead_of_silently_overwriting(self):
        registry = PatternRegistry()
        registry.register(_make_pattern("PAT-001", name="first"))

        with pytest.raises(ValueError, match="Duplicate correlation pattern id"):
            registry.register(_make_pattern("PAT-001", name="second"))

        # The original registration must survive the failed second attempt.
        assert registry.get("PAT-001").name == "first"

    def test_error_message_names_both_patterns(self):
        registry = PatternRegistry()
        registry.register(_make_pattern("PAT-001", name="first"))

        with pytest.raises(ValueError, match="first.*second"):
            registry.register(_make_pattern("PAT-001", name="second"))
