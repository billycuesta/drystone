from pathlib import Path

from drystone.prompts.template_loader import list_available_templates, load_template
from drystone.skills.registry import skill_names

TEMPLATE_DIR = Path("drystone/prompts/templates")


def test_every_registered_skill_has_specific_audit_template():
    templates = list_available_templates()
    missing = sorted(set(skill_names()) - set(templates))
    assert missing == []


def test_cloudtrail_events_and_ser_templates_extend_base():
    cloudtrail = load_template("cloudtrail_events")
    ser = load_template("sistemas_explotables_red")

    assert "CloudTrail Events Threat Activity Analysis" in cloudtrail
    assert "Exploitable Network Systems Analysis" in ser
    assert "EVIDENCE-BASED ANALYSIS REQUIREMENTS" in cloudtrail
    assert "EVIDENCE-BASED ANALYSIS REQUIREMENTS" in ser


def test_orphan_pentest_analysis_template_removed():
    assert not (TEMPLATE_DIR / "pentest_analysis.xml").exists()
