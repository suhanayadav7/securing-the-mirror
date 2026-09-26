import pytest

pytest.importorskip("wntr")
from mirror.framework import Maturity  # noqa: E402
from mirror.gateway import GatewayConfig  # noqa: E402
from mirror.hydraulics import impact_by_level, simulate_network  # noqa: E402
from mirror.simulate import SimConfig, monte_carlo  # noqa: E402


def test_no_attack_no_harm():
    for scenario in ("dosing_setpoint_tamper", "plc_takeover"):
        impact = simulate_network(scenario, 0)
        assert impact.nodes_affected == 0 and impact.harmful_volume_m3 == 0


def test_overdose_volume_grows_with_attack_duration():
    volumes = [simulate_network("dosing_setpoint_tamper", m).harmful_volume_m3 for m in (15, 45, 360)]
    assert volumes[0] < volumes[1] < volumes[2]


def test_tanks_buffer_short_pump_outages():
    assert simulate_network("plc_takeover", 45).nodes_affected < 5
    assert simulate_network("plc_takeover", 1440).nodes_affected > 300


def test_governance_levels_limit_network_damage():
    impacts = impact_by_level("dosing_setpoint_tamper")
    assert impacts[Maturity.UNGOVERNED].harmful_volume_m3 > impacts[Maturity.MONITORED].harmful_volume_m3 > 0
    assert impacts[Maturity.VALIDATED].harmful_volume_m3 == impacts[Maturity.RESILIENT].harmful_volume_m3 == 0


def test_fallible_reviewer_makes_level3_imperfect_but_better_than_level2():
    cfg = SimConfig(gateway=GatewayConfig.realistic())
    l2, l3, l4 = (monte_carlo("chlorine_fdi", lvl, cfg, runs=60) for lvl in (2, 3, 4))
    assert l4["p_harm"] == 0
    assert 0 < l3["p_harm"] < l2["p_harm"]


def test_reviewer_who_always_misses_gives_no_protection_from_review():
    cfg = SimConfig(gateway=GatewayConfig(reviewer_miss_rate=1.0))
    assert monte_carlo("dosing_setpoint_tamper", 3, cfg, runs=5)["p_contained"] == 0
