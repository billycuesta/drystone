"""Tests for findings normalizer - skill-agnostic implementation."""

import pytest
from datetime import datetime

from drystone.models.findings import Finding, FindingsSummary
from drystone.validation.findings_normalizer import FindingsNormalizer


# ===== FIXTURES =====

@pytest.fixture
def sample_checklist_iam():
    """Sample IAM security checklist."""
    return {
        'skill': 'iam',
        'items': [
            {
                'id': 'IAM-001',
                'severity': 'Critical',
                'title': 'Root account must have MFA enabled',
            },
            {
                'id': 'IAM-007',
                'severity': 'Medium',
                'title': 'Inline policies should be migrated to managed',
            },
            {
                'id': 'IAM-011',
                'severity': 'Critical',
                'title': 'Access keys must be rotated every 90 days',
            },
            {
                'id': 'IAM-015',
                'severity': 'High',
                'title': 'Users must have MFA enabled',
            },
        ]
    }


@pytest.fixture
def sample_checklist_exposure():
    """Sample Exposure security checklist."""
    return {
        'skill': 'exposure',
        'items': [
            {
                'id': 'EXP-001',
                'severity': 'Critical',
                'title': 'S3 buckets must not be publicly readable',
            },
            {
                'id': 'EXP-005',
                'severity': 'High',
                'title': 'RDS instances must not be publicly accessible',
            },
            {
                'id': 'EXP-012',
                'severity': 'Medium',
                'title': 'Snapshots must have restricted permissions',
            },
        ]
    }


@pytest.fixture
def sample_checklist_network():
    """Sample Network security checklist."""
    return {
        'skill': 'network',
        'items': [
            {
                'id': 'NET-001',
                'severity': 'Critical',
                'title': 'Security groups must restrict SSH access',
            },
            {
                'id': 'NET-005',
                'severity': 'High',
                'title': 'VPCs must use NACLs',
            },
            {
                'id': 'NET-010',
                'severity': 'Medium',
                'title': 'Flow logs must be enabled',
            },
        ]
    }


@pytest.fixture
def sample_findings_with_issues():
    """Sample findings with normalization issues."""
    return [
        # Issue 1: Sub-ID that needs normalization
        Finding(
            id='IAM-008-001',  # Should be IAM-008
            severity='High',
            risk_score=7.5,
            title='Test finding 1',
            description='Description 1',
            remediation='Remediation 1',
        ),
        # Issue 2: False positive with DISREGARD marker
        Finding(
            id='IAM-009',
            severity='Medium',
            risk_score=4.0,
            title='DISREGARD THIS FINDING - test',
            description='This should be filtered',
            remediation='N/A',
        ),
        # Issue 3: Invalid ID not in checklist
        Finding(
            id='IAM-999',
            severity='Medium',
            risk_score=3.0,
            title='Invalid finding',
            description='This ID does not exist in checklist',
            remediation='N/A',
        ),
        # Issue 4: Severity mismatch (checklist says Medium, AI said High)
        Finding(
            id='IAM-007',
            severity='High',  # Wrong: checklist says Medium
            risk_score=7.5,
            title='Inline policies issue',
            description='Correct ID but wrong severity',
            remediation='Migrate to managed policies',
        ),
        # Correct finding: no issues
        Finding(
            id='IAM-001',
            severity='Critical',
            risk_score=9.5,
            title='Root account without MFA',
            description='Root account has no MFA devices',
            remediation='Enable MFA on root account',
        ),
    ]


# ===== TESTS: Normalize ID =====

class TestNormalizeID:
    """Test ID normalization (removing sub-IDs)."""

    def test_normalize_id_iam_simple(self, sample_checklist_iam):
        """Test simple IAM IDs (already normalized)."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        assert normalizer._normalize_id('IAM-001') == 'IAM-001'
        assert normalizer._normalize_id('IAM-007') == 'IAM-007'
        assert normalizer._normalize_id('IAM-015') == 'IAM-015'

    def test_normalize_id_iam_with_subids(self, sample_checklist_iam):
        """Test IAM IDs with sub-IDs (need normalization)."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # Sub-IDs should be stripped
        assert normalizer._normalize_id('IAM-008-001') == 'IAM-008'
        assert normalizer._normalize_id('IAM-020-002') == 'IAM-020'
        assert normalizer._normalize_id('IAM-001-999') == 'IAM-001'

    def test_normalize_id_exposure(self, sample_checklist_exposure):
        """Test Exposure skill IDs."""
        normalizer = FindingsNormalizer(sample_checklist_exposure, skill_name='exposure')

        assert normalizer._normalize_id('EXP-001') == 'EXP-001'
        assert normalizer._normalize_id('EXP-005-001') == 'EXP-005'
        assert normalizer._normalize_id('EXP-012-999') == 'EXP-012'

    def test_normalize_id_network(self, sample_checklist_network):
        """Test Network skill IDs."""
        normalizer = FindingsNormalizer(sample_checklist_network, skill_name='network')

        assert normalizer._normalize_id('NET-001') == 'NET-001'
        assert normalizer._normalize_id('NET-005-001') == 'NET-005'
        assert normalizer._normalize_id('NET-010-sub') == 'NET-010'

    def test_normalize_id_vulns(self):
        """Test VULN skill IDs."""
        checklist = {
            'items': [
                {'id': 'VULN-001', 'severity': 'Critical'},
                {'id': 'VULN-005', 'severity': 'High'},
            ]
        }
        normalizer = FindingsNormalizer(checklist, skill_name='vulns')

        assert normalizer._normalize_id('VULN-001') == 'VULN-001'
        assert normalizer._normalize_id('VULN-005-001') == 'VULN-005'


# ===== TESTS: False Positive Detection =====

class TestFalsePositiveDetection:
    """Test filtering of false positives."""

    def test_false_positive_disregard_in_title(self, sample_checklist_iam):
        """Test detection of DISREGARD marker in title."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        finding = Finding(
            id='IAM-007',
            severity='Medium',
            risk_score=4.0,
            title='DISREGARD THIS FINDING - error',
            description='Should be filtered',
            remediation='N/A',
        )

        assert normalizer._is_false_positive(finding) is True

    def test_false_positive_disregard_in_description(self, sample_checklist_iam):
        """Test detection of DISREGARD marker in description."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        finding = Finding(
            id='IAM-007',
            severity='Medium',
            risk_score=4.0,
            title='Real title',
            description='DISREGARD THIS - was generated by mistake',
            remediation='N/A',
        )

        assert normalizer._is_false_positive(finding) is True

    def test_false_positive_invalid_id(self, sample_checklist_iam):
        """Test detection of IDs not in checklist."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        finding = Finding(
            id='IAM-999',  # Not in checklist
            severity='Medium',
            risk_score=4.0,
            title='Finding with invalid ID',
            description='This ID does not exist',
            remediation='N/A',
        )

        assert normalizer._is_false_positive(finding) is True

    def test_not_false_positive_valid_finding(self, sample_checklist_iam):
        """Test that valid findings are NOT flagged as false positives."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        finding = Finding(
            id='IAM-001',
            severity='Critical',
            risk_score=9.5,
            title='Root account without MFA',
            description='Root account has no MFA devices configured',
            remediation='Enable MFA on root account',
        )

        assert normalizer._is_false_positive(finding) is False


# ===== TESTS: Severity Calibration =====

class TestSeverityCalibration:
    """Test severity calibration against checklist constraints."""

    def test_calibrate_severity_matches_checklist(self, sample_checklist_iam):
        """Test calibration when AI model got severity right."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # IAM-001 is Critical in checklist, AI said Critical
        severity, score = normalizer._calibrate_severity('IAM-001', 'Critical', 9.5)

        assert severity == 'Critical'
        assert 8.5 <= score <= 10.0
        assert score == 9.5  # Unchanged

    def test_calibrate_severity_mismatch_high_to_medium(self, sample_checklist_iam):
        """Test calibration when AI said High but checklist says Medium."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # IAM-007 is Medium in checklist, AI said High
        severity, score = normalizer._calibrate_severity('IAM-007', 'High', 7.5)

        assert severity == 'Medium'
        assert 3.0 <= score <= 5.9
        # Should be middle of range
        assert score == pytest.approx(4.45, abs=0.1)

    def test_calibrate_severity_clamp_to_range(self, sample_checklist_iam):
        """Test clamping of risk_score to severity range."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # IAM-001 is Critical (8.5-10.0), AI said 12.0 (out of range)
        severity, score = normalizer._calibrate_severity('IAM-001', 'Critical', 12.0)

        assert severity == 'Critical'
        assert score == 10.0  # Clamped to max

    def test_calibrate_severity_clamp_low(self, sample_checklist_iam):
        """Test clamping to minimum of range."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # IAM-007 is Medium (3.0-5.9), AI said 1.0 (below range)
        severity, score = normalizer._calibrate_severity('IAM-007', 'Medium', 1.0)

        assert severity == 'Medium'
        assert score == 3.0  # Clamped to min

    def test_calibrate_severity_invalid_id(self, sample_checklist_iam):
        """Test calibration of invalid ID (not in checklist)."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        # IAM-999 not in checklist: return unchanged
        severity, score = normalizer._calibrate_severity('IAM-999', 'High', 7.0)

        assert severity == 'High'
        assert score == 7.0


# ===== TESTS: Full Normalization =====

class TestFullNormalization:
    """Test complete normalization pipeline."""

    def test_normalize_with_various_issues(
        self, sample_checklist_iam, sample_findings_with_issues
    ):
        """Test normalization with multiple issues."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        normalized = normalizer.normalize(sample_findings_with_issues)

        # Should have 2 findings:
        # - Issue 1 (IAM-008-001): filtered (invalid ID)
        # - Issue 2 (DISREGARD): filtered
        # - Issue 3 (IAM-999): filtered (invalid ID)
        # - Issue 4 (IAM-007): normalized (severity corrected)
        # - Correct (IAM-001): unchanged
        assert len(normalized) == 2

        # Check Issue 4 was normalized
        iam007 = next((f for f in normalized if f.id == 'IAM-007'), None)
        assert iam007 is not None
        assert iam007.severity == 'Medium'  # Corrected from High
        assert 3.0 <= iam007.risk_score <= 5.9  # Recalibrated

        # Check correct finding unchanged
        iam001 = next((f for f in normalized if f.id == 'IAM-001'), None)
        assert iam001 is not None
        assert iam001.severity == 'Critical'
        assert iam001.risk_score == 9.5

    def test_normalize_removes_duplicates(self, sample_checklist_iam):
        """Test that duplicate findings (same normalized ID) are removed."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        findings = [
            Finding(
                id='IAM-001-001',
                severity='Critical',
                risk_score=9.5,
                title='Root without MFA (first)',
                description='desc1',
                remediation='remediate',
            ),
            Finding(
                id='IAM-001-002',
                severity='Critical',
                risk_score=9.0,
                title='Root without MFA (second)',
                description='desc2',
                remediation='remediate',
            ),
        ]

        normalized = normalizer.normalize(findings)

        # Should have only 1 finding (duplicate removed)
        assert len(normalized) == 1
        assert normalized[0].id == 'IAM-001'
        # First occurrence is kept
        assert 'first' in normalized[0].title


# ===== TESTS: Summary Recalculation =====

class TestSummaryRecalculation:
    """Test recalculation of summary statistics."""

    def test_recalculate_summary_empty(self, sample_checklist_iam):
        """Test summary for empty findings list."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        summary = normalizer.recalculate_summary([])

        assert summary.total_findings == 0
        assert summary.critical == 0
        assert summary.high == 0
        assert summary.medium == 0
        assert summary.low == 0
        assert summary.overall_risk_score == 0.0

    def test_recalculate_summary_single_finding(self, sample_checklist_iam):
        """Test summary with single finding."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        findings = [
            Finding(
                id='IAM-001',
                severity='Critical',
                risk_score=9.5,
                title='Root',
                description='desc',
                remediation='remediate',
            )
        ]

        summary = normalizer.recalculate_summary(findings)

        assert summary.total_findings == 1
        assert summary.critical == 1
        assert summary.high == 0
        assert summary.overall_risk_score == 9.5

    def test_recalculate_summary_weighted_average(self, sample_checklist_iam):
        """Test weighted average calculation for overall_risk_score.

        Weights:
        - Critical: 3x
        - High: 2x
        - Medium: 1x
        - Low: 0.5x
        """
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        findings = [
            Finding(
                id='IAM-001',
                severity='Critical',
                risk_score=10.0,  # weight 3
                title='Critical',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='IAM-015',
                severity='High',
                risk_score=7.0,  # weight 2
                title='High',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='IAM-007',
                severity='Medium',
                risk_score=4.0,  # weight 1
                title='Medium',
                description='desc',
                remediation='remediate',
            ),
        ]

        summary = normalizer.recalculate_summary(findings)

        # weighted_sum = (10.0 * 3) + (7.0 * 2) + (4.0 * 1) = 30 + 14 + 4 = 48
        # total_weight = 3 + 2 + 1 = 6
        # overall = 48 / 6 = 8.0
        assert summary.overall_risk_score == pytest.approx(8.0, abs=0.1)

    def test_recalculate_summary_counts(self, sample_checklist_iam):
        """Test severity counts in summary."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')

        findings = [
            Finding(
                id='IAM-001',
                severity='Critical',
                risk_score=9.5,
                title='Critical1',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='IAM-001',
                severity='Critical',
                risk_score=9.0,
                title='Critical2',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='IAM-015',
                severity='High',
                risk_score=7.0,
                title='High1',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='IAM-007',
                severity='Medium',
                risk_score=4.0,
                title='Medium1',
                description='desc',
                remediation='remediate',
            ),
        ]

        summary = normalizer.recalculate_summary(findings)

        assert summary.total_findings == 4
        assert summary.critical == 2
        assert summary.high == 1
        assert summary.medium == 1
        assert summary.low == 0


# ===== TESTS: Skill-Agnostic Functionality =====

class TestSkillAgnostic:
    """Test that normalizer works across different skills."""

    def test_normalize_iam_skill(self, sample_checklist_iam, sample_findings_with_issues):
        """Test normalization for IAM skill."""
        normalizer = FindingsNormalizer(sample_checklist_iam, skill_name='iam')
        normalized = normalizer.normalize(sample_findings_with_issues)

        assert len(normalized) == 2  # 2 valid findings
        assert all('IAM' in f.id for f in normalized)

    def test_normalize_exposure_skill(self, sample_checklist_exposure):
        """Test normalization for Exposure skill."""
        normalizer = FindingsNormalizer(sample_checklist_exposure, skill_name='exposure')

        findings = [
            Finding(
                id='EXP-001-001',  # Sub-ID
                severity='Critical',
                risk_score=9.5,
                title='S3 bucket public',
                description='desc',
                remediation='remediate',
            ),
            Finding(
                id='EXP-005',
                severity='Medium',  # Wrong: checklist says High
                risk_score=4.0,
                title='RDS public',
                description='desc',
                remediation='remediate',
            ),
        ]

        normalized = normalizer.normalize(findings)

        assert len(normalized) == 2

        exp001 = next((f for f in normalized if f.id == 'EXP-001'), None)
        assert exp001 is not None
        assert exp001.severity == 'Critical'

        exp005 = next((f for f in normalized if f.id == 'EXP-005'), None)
        assert exp005 is not None
        assert exp005.severity == 'High'  # Corrected

    def test_normalize_network_skill(self, sample_checklist_network):
        """Test normalization for Network skill."""
        normalizer = FindingsNormalizer(sample_checklist_network, skill_name='network')

        findings = [
            Finding(
                id='NET-001',
                severity='Critical',
                risk_score=9.0,
                title='SG allows SSH',
                description='desc',
                remediation='remediate',
            ),
        ]

        normalized = normalizer.normalize(findings)

        assert len(normalized) == 1
        assert normalized[0].id == 'NET-001'
        assert normalized[0].severity == 'Critical'
