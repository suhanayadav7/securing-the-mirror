import pytest

from mirror.data import INCIDENTS, UTILITY_HANDOFFS
from mirror.framework import Assessment, Handoff, Maturity


def test_table_ii_composites_match_paper():
    # Table II reports these to one decimal place
    assert [round(h.composite + 1e-9, 1) for h in UTILITY_HANDOFFS] == [4.0, 3.8, 2.3, 2.0]


def test_section_vi_composites_match_paper():
    assert [h.handoff.composite for h in INCIDENTS] == [4.5, 4.25, 4.25, 4.25]


def test_scores_must_be_1_to_5():
    with pytest.raises(ValueError):
        Handoff("bad", 0, 3, 3, 3)
    with pytest.raises(ValueError):
        Handoff("bad", 3, 3, 6, 3)


def test_required_maturity_rules():
    assert Handoff("autonomous + severe", 3, 3, 4, 4).required_maturity == Maturity.RESILIENT
    assert Handoff("severe, human reviewed", 2, 2, 2, 4).required_maturity == Maturity.VALIDATED
    assert Handoff("high composite", 4, 4, 2, 2).required_maturity == Maturity.VALIDATED
    assert Handoff("low risk", 1, 2, 2, 2).required_maturity == Maturity.MONITORED


def test_paper_governance_gap_is_found():
    """Section IV-D: water quality and pressure/flow are the priority gaps."""
    a = Assessment(UTILITY_HANDOFFS)
    assert [h.name for h in a.priority_gaps()] == [
        "Water quality (inline sensors)",
        "Pressure/flow (distribution network)",
    ]
    assert [h.name for h in a.mismatches()] == [h.name for h in a.priority_gaps()]


def test_recommendations_cover_each_missing_level():
    h = Handoff("x", 5, 5, 5, 5, Maturity.UNGOVERNED)
    recs = " ".join(h.recommendations())
    assert "internet exposure" in recs      # -> Level 2
    assert "accountable reviewer" in recs  # -> Level 3
    assert "Cryptographically" in recs      # -> Level 4
    assert Handoff("y", 1, 1, 1, 1, Maturity.RESILIENT).recommendations() == []
