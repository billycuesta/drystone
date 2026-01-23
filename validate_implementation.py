#!/usr/bin/env python3.9
"""Quick validation script for variance reduction implementation."""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def test_normalizer_imports():
    """Test 1: Normalizer imports successfully."""
    try:
        from drystone.validation.findings_normalizer import FindingsNormalizer
        print("✅ Test 1: Normalizer imports successfully")
        return True
    except Exception as e:
        print(f"❌ Test 1: Failed to import normalizer: {e}")
        return False


def test_base_skill_has_normalize_method():
    """Test 2: BaseSkill has _normalize_findings method."""
    try:
        from drystone.skills.base import BaseSkill
        assert hasattr(BaseSkill, '_normalize_findings'), "BaseSkill missing _normalize_findings"
        print("✅ Test 2: BaseSkill has _normalize_findings method")
        return True
    except Exception as e:
        print(f"❌ Test 2: {e}")
        return False


def test_iam_skill_uses_normalization():
    """Test 3: IAMSkill uses normalization in analyze."""
    try:
        from drystone.skills.iam import IAMSkill
        import inspect

        source = inspect.getsource(IAMSkill.analyze)
        assert '_normalize_findings' in source, "IAMSkill.analyze doesn't call _normalize_findings"
        print("✅ Test 3: IAMSkill uses normalization in analyze method")
        return True
    except Exception as e:
        print(f"❌ Test 3: {e}")
        return False


def test_normalizer_functionality():
    """Test 4: Normalizer basic functionality."""
    try:
        from drystone.models.findings import Finding
        from drystone.validation.findings_normalizer import FindingsNormalizer

        checklist = {
            'items': [
                {'id': 'IAM-001', 'severity': 'Critical'},
                {'id': 'IAM-007', 'severity': 'Medium'},
            ]
        }

        normalizer = FindingsNormalizer(checklist, skill_name='iam')

        # Test ID normalization
        assert normalizer._normalize_id('IAM-001') == 'IAM-001'
        assert normalizer._normalize_id('IAM-008-001') == 'IAM-008'

        # Test false positive detection
        fp_finding = Finding(
            id='IAM-007',
            severity='Medium',
            risk_score=4.0,
            title='DISREGARD THIS FINDING',
            description='test',
            remediation='test',
        )
        assert normalizer._is_false_positive(fp_finding) is True

        # Test severity calibration
        sev, score = normalizer._calibrate_severity('IAM-007', 'High', 7.5)
        assert sev == 'Medium', f"Expected Medium, got {sev}"
        assert 3.0 <= score <= 5.9, f"Expected score in 3.0-5.9, got {score}"

        print("✅ Test 4: Normalizer basic functionality works")
        return True
    except Exception as e:
        print(f"❌ Test 4: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_prompt_changes():
    """Test 5: Agent prompts are skill-agnostic."""
    try:
        from drystone.agent.client import AgentClient
        import inspect

        # Get system prompt
        agent = AgentClient()  # Default config
        sys_prompt = agent._get_system_prompt()

        # Check for skill-agnostic markers
        assert 'SKILL-AGNOSTIC' in sys_prompt or 'skill_name' in sys_prompt or 'UNIVERSAL' in sys_prompt
        assert 'DISREGARD' not in sys_prompt  # Not hardcoded for IAM

        # Check for anti-varianza rules
        assert 'sub-ID' in sys_prompt or 'sub-ids' in sys_prompt
        assert 'NUNCA' in sys_prompt

        print("✅ Test 5: Agent prompts are skill-agnostic")
        return True
    except Exception as e:
        print(f"❌ Test 5: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_severity_guide_generation():
    """Test 6: Severity guide generation from checklist."""
    try:
        from drystone.agent.client import AgentClient

        agent = AgentClient()  # Default config

        checklist = {
            'items': [
                {'id': 'IAM-001', 'severity': 'Critical', 'title': 'Root MFA'},
                {'id': 'IAM-007', 'severity': 'Medium', 'title': 'Inline policies'},
                {'id': 'IAM-015', 'severity': 'High', 'title': 'User MFA'},
            ]
        }

        guide = agent._generate_severity_guide(checklist)

        # Check that guide contains severity examples
        assert 'CRITICAL' in guide
        assert 'Critical' in guide or 'CRITICAL' in guide
        assert 'IAM-001' in guide or 'Root' in guide

        print("✅ Test 6: Severity guide generation works")
        return True
    except Exception as e:
        print(f"❌ Test 6: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all validation tests."""
    print("\n" + "="*60)
    print("VALIDATING VARIANCE REDUCTION IMPLEMENTATION")
    print("="*60 + "\n")

    tests = [
        test_normalizer_imports,
        test_base_skill_has_normalize_method,
        test_iam_skill_uses_normalization,
        test_normalizer_functionality,
        test_prompt_changes,
        test_severity_guide_generation,
    ]

    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"❌ {test.__name__}: Unexpected error: {e}")
            results.append(False)
        print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("="*60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("="*60)

    if passed == total:
        print("\n✅ ALL TESTS PASSED - Implementation is correct!\n")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed - please review\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
