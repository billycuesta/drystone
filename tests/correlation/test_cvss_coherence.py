"""Tests for CVSS score coherence (Fix 2)."""

import pytest
from unittest.mock import MagicMock

from drystone.correlation.engine import CorrelationEngine


def _mock_correlated_finding(compound_risk_score, severity="High"):
    f = MagicMock()
    f.compound_risk_score = compound_risk_score
    f.severity = severity
    return f


class TestCVSSScoreCoherence:
    """Fix 2: CVSS vector must be derived from compound_risk_score, not severity label."""

    def setup_method(self):
        self.engine = CorrelationEngine.__new__(CorrelationEngine)

    def test_critical_score_gets_critical_vector(self):
        """Score >=9.0 should produce Critical vector (AV:N/AC:L/PR:N/UI:N/S:C)."""
        f = _mock_correlated_finding(9.5, severity="Critical")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 9.5
        assert "AV:N/AC:L/PR:N/UI:N/S:C" in cvss.vector_string

    def test_high_score_gets_high_vector(self):
        """Score 7.0-8.9 should produce High vector."""
        f = _mock_correlated_finding(7.8, severity="High")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 7.8
        assert "PR:L" in cvss.vector_string  # High vector has PR:L
        assert "S:U" in cvss.vector_string

    def test_medium_score_gets_medium_vector(self):
        """Score 4.0-6.9 should produce Medium vector."""
        f = _mock_correlated_finding(5.5, severity="Medium")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 5.5
        assert "AV:A" in cvss.vector_string  # Medium vector has AV:A

    def test_low_score_gets_low_vector(self):
        """Score <4.0 should produce Low vector."""
        f = _mock_correlated_finding(2.5, severity="Low")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 2.5
        assert "AV:L" in cvss.vector_string

    def test_score_severity_mismatch_uses_score(self):
        """If severity says 'High' but score is 3.9 → vector should be Low."""
        f = _mock_correlated_finding(3.9, severity="High")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 3.9
        assert "AV:L" in cvss.vector_string  # Low vector, not High

    def test_score_rounding(self):
        """base_score should be rounded to 1 decimal."""
        f = _mock_correlated_finding(7.84999, severity="High")
        cvss = self.engine.calculate_cvss_score(f)
        assert cvss.base_score == 7.8
