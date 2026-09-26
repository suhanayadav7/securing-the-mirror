import pytest

from mirror.__main__ import main
from mirror.attacks import SCENARIOS
from mirror.framework import Maturity
from mirror.simulate import run

L1, L2, L3, L4 = Maturity


@pytest.mark.parametrize("level", list(Maturity))
def test_baseline_is_safe_with_no_false_alarms(level):
    r = run("baseline", level)
    assert r.outcome == "Safe"
    assert r.alerts == []


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s != "baseline"])
def test_every_attack_harms_an_ungoverned_twin(scenario):
    r = run(scenario, L1)
    assert r.outcome == "Harm"
    assert r.detected_after is None


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s != "baseline"])
def test_resilient_level_prevents_harm(scenario):
    r = run(scenario, L4)
    assert r.outcome in ("Safe", "Near miss")
    assert r.contained_after is not None and r.contained_after <= 20


@pytest.mark.parametrize("scenario", ["chlorine_fdi", "pressure_fdi", "dosing_setpoint_tamper"])
def test_level3_review_blocks_obvious_tampering(scenario):
    r = run(scenario, L3)
    assert r.outcome == "Safe"
    assert r.contained_after == 10  # the review delay


def test_level2_detects_but_harm_depends_on_operator():
    r = run("dosing_setpoint_tamper", L2)
    assert r.detected_after == 0
    assert r.contained_after == 45
    assert r.outcome == "Harm"


def test_aliquippa_is_prevented_by_basic_hygiene():
    """Section VI-D: the Level 1 -> 2 transition alone stops an internet-exposed PLC takeover."""
    assert run("plc_takeover", L1).outcome == "Harm"
    assert run("plc_takeover", L2).outcome == "Safe"


def test_only_level4_sees_replay_and_stealthy_drift():
    for scenario in ("replay_masking", "stealthy_drift"):
        assert run(scenario, L3).outcome == "Harm"
        assert run(scenario, L4).outcome in ("Safe", "Near miss")


def test_results_are_deterministic():
    assert run("chlorine_fdi", L2).summary() == run("chlorine_fdi", L2).summary()


def test_cli_runs(capsys):
    main(["assess"])
    main(["simulate", "chlorine_fdi", "--level", "3"])
    main(["matrix", "--duration", "120"])
    out = capsys.readouterr().out
    assert "Water quality" in out and "chlorine_fdi" in out
