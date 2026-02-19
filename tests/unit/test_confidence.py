from drystone.validation.confidence import compute_skill_confidence


def test_confidence_high_when_deterministic_dominates():
    out = compute_skill_confidence(
        total_checks=20,
        deterministic_checks=18,
        llm_checks=2,
        partial_run=False,
    )
    assert out["level"] == "high"
    assert float(out["score"]) >= 0.85


def test_confidence_drops_on_partial_run():
    out = compute_skill_confidence(
        total_checks=20,
        deterministic_checks=10,
        llm_checks=10,
        partial_run=True,
    )
    assert out["level"] in {"low", "medium"}
    assert float(out["score"]) < 0.7
