"""Tests for drystone/skills/registry.py (P1 #1 skill auto-discovery)."""

import drystone.skills as skills_pkg
import drystone.skills.registry as registry


def _reset_cache():
    registry._registry_cache = None
    registry._id_prefix_cache = None


def test_discover_skills_finds_all_real_skills():
    _reset_cache()
    manifests = registry.discover_skills(force_refresh=True)

    assert manifests["iam"].skill_class.__name__ == "IAMSkill"
    assert manifests["messaging"].display_name == "Messaging"
    assert manifests["cloudtrail_events"].skill_class.__name__ == "CloudTrailEventsSkill"
    assert len(manifests) == 16
    _reset_cache()


def test_wizard_choices_excludes_pentest_only_skills():
    _reset_cache()
    names = {m.name for m in registry.wizard_choices()}

    assert "recon" not in names
    assert "sistemas_explotables_red" not in names
    assert "iam" in names
    assert len(names) == 14
    _reset_cache()


def test_discover_skills_is_cached_until_force_refresh(monkeypatch):
    _reset_cache()
    first = registry.discover_skills()
    calls = {"n": 0}
    real_import_module = registry.importlib.import_module

    def counting_import(*args, **kwargs):
        calls["n"] += 1
        return real_import_module(*args, **kwargs)

    monkeypatch.setattr(registry.importlib, "import_module", counting_import)
    second = registry.discover_skills()  # cached — must NOT re-import

    assert first is second
    assert calls["n"] == 0
    _reset_cache()


def test_discover_skills_picks_up_a_new_skill_with_zero_edits_elsewhere(tmp_path, monkeypatch):
    """Regression test for the actual P1 #1 promise: a brand-new skill package
    needs no edits outside its own folder to be discovered. Points the
    registry's scan root at an isolated temp directory containing a single
    fake skill, so this doesn't touch (or depend on) the real 16 skills.
    """
    fake_skill_dir = tmp_path / "totally_new_skill"
    fake_skill_dir.mkdir()
    (fake_skill_dir / "__init__.py").write_text(
        "from drystone.skills.base import BaseSkill\n"
        "\n"
        "class TotallyNewSkill(BaseSkill):\n"
        "    @property\n"
        "    def name(self):\n"
        "        return 'totally_new_skill'\n"
        "    def collect(self, aws_client, session):\n"
        "        pass\n"
        "\n"
        "SKILL_NAME = 'totally_new_skill'\n"
        "SKILL_DISPLAY_NAME = 'Totally New Skill'\n"
        "SKILL_CLASS = TotallyNewSkill\n"
        "SKILL_WIZARD_SELECTABLE = True\n"
        "SKILL_WIZARD_LABEL = 'Totally New Skill Audit'\n"
        "SKILL_WIZARD_ORDER = 1\n"
    )

    _reset_cache()
    monkeypatch.setattr(skills_pkg, "__path__", [str(tmp_path)])
    try:
        manifests = registry.discover_skills(force_refresh=True)
        assert "totally_new_skill" in manifests
        assert manifests["totally_new_skill"].display_name == "Totally New Skill"
        assert manifests["totally_new_skill"].class_name == "TotallyNewSkill"

        names = registry.skill_names()
        assert names == ["totally_new_skill"]

        wizard_names = {m.name for m in registry.wizard_choices()}
        assert wizard_names == {"totally_new_skill"}
    finally:
        _reset_cache()


class TestSkillNameByIdPrefix:
    """Regression tests for the reverse (ID-prefix -> skill_name) lookup used to
    fix correlation/engine.py rec AJ (previously assumed skill_name == prefix.lower())."""

    def test_maps_real_prefixes_to_real_skill_names(self):
        _reset_cache()
        mapping = registry.skill_name_by_id_prefix(force_refresh=True)

        # All 16 real (prefix -> skill_name) pairs. correlation/engine.py's old
        # `finding.id.split("-")[0].lower()` assumed skill_name == prefix.lower(),
        # which only happens to hold for iam/ecr/waf/kms/cicd/recon -- for the
        # other 10 (exposure, network, vulns, hardening, alerting, secretsmanager,
        # compute, messaging, cloudtrail_events, sistemas_explotables_red) it
        # produced a wrong skill label.
        assert mapping == {
            "iam": "iam",
            "exp": "exposure",
            "net": "network",
            "vuln": "vulns",
            "hrd": "hardening",
            "alrt": "alerting",
            "ecr": "ecr",
            "sm": "secretsmanager",
            "waf": "waf",
            "kms": "kms",
            "cicd": "cicd",
            "comp": "compute",
            "msg": "messaging",
            "ctef": "cloudtrail_events",
            "recon": "recon",
            "ser": "sistemas_explotables_red",
        }

    def test_result_is_cached_until_force_refresh(self):
        _reset_cache()
        first = registry.skill_name_by_id_prefix()
        second = registry.skill_name_by_id_prefix()
        assert first is second
        _reset_cache()
