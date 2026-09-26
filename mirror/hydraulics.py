"""Network-scale consequences on a real hydraulic model (EPANET, via WNTR).

The control-loop simulator (simulate.py) answers *how long* a tampered command stays in
effect at each governance level. This module answers *what that does to the network*: it
replays the attack on C-Town - the EPANET model behind the BATADAL dataset (388 junctions,
7 tanks, 11 pumps) - and measures how far the damage spreads.

    dosing_setpoint_tamper  chlorine source at the reservoir driven to the dosing pump's
                            maximum (Oldsmar / Kemuri); EPANET water-quality simulation
    plc_takeover            main pumping station (PU1, PU2) stopped (Aliquippa)
"""

from __future__ import annotations

import math
import tempfile
import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np
import wntr
from wntr.network import LinkStatus
from wntr.network.controls import AndCondition, ControlAction, ControlPriority, Rule, SimTimeCondition

from .framework import Maturity
from .simulate import Result, SimConfig, run
from .twin import CHLORINE_SAFE, DOSE_MAX

NETWORK = Path(__file__).resolve().parent.parent / "data" / "networks" / "CTOWN.INP"
NETWORK_URL = "https://www.batadal.net/data/CTOWN.INP"

STEP_S = 900                     # 15-minute hydraulic, pattern and reporting step
NORMAL_DOSE = 1.0                # mg/L chlorine at the source
BULK_DECAY_PER_DAY = -0.5        # first-order bulk chlorine decay
MIN_SERVICE_PRESSURE = 14.0      # m (~20 psi): below this, backflow/contamination risk
ATTACKED_PUMPS = ("PU1", "PU2")  # C-Town's main station
DOSING_NODES = ("J285", "J280")  # suction side of PU1/PU2, where treated water leaves R1
HYDRAULIC_SCENARIOS = ("dosing_setpoint_tamper", "plc_takeover")


@dataclass
class NetworkImpact:
    scenario: str
    attack_minutes: int
    nodes_affected: int              # demand junctions harmed that are not harmed in the no-attack run
    demand_nodes: int
    first_harm_h: float | None       # hours after attack start until the first junction is harmed
    harm_hours: float                # hours during which at least one junction is harmed
    harmful_volume_m3: float         # over-chlorinated water delivered, or demand left unserved
    peak_value: float                # max chlorine (mg/L) or min pressure (m) at any demand junction
    series_t_h: list[float]
    series_affected: list[int]       # harmed junction count over time

    def as_dict(self) -> dict:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        d.pop("series_t_h"), d.pop("series_affected")
        return d


def _load(path: Path = NETWORK) -> wntr.network.WaterNetworkModel:
    if not path.exists():
        import urllib.request
        path.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(NETWORK_URL, path)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        wn = wntr.network.WaterNetworkModel(str(path))
    # refine the hourly patterns to 15-minute steps so short attacks are represented exactly
    factor = int(wn.options.time.pattern_timestep // STEP_S)
    if factor > 1:
        for name in wn.pattern_name_list:
            pat = wn.get_pattern(name)
            pat.multipliers = np.repeat(pat.multipliers, factor)
        wn.options.time.pattern_timestep = STEP_S
    wn.options.time.hydraulic_timestep = STEP_S
    wn.options.time.report_timestep = STEP_S
    wn.options.time.rule_timestep = 60
    # pressure-driven demand: an empty network delivers less water instead of negative pressure
    wn.options.hydraulic.demand_model = "PDD"
    wn.options.hydraulic.minimum_pressure = 0.0
    wn.options.hydraulic.required_pressure = 20.0
    # C-Town schedules PU1/PU2 with simple controls, which ignore priority; restate them as
    # equal-priority rules so an attacker's higher-priority rule can override them
    for name in list(wn.control_name_list):
        control = wn.get_control(name)
        if any(a.target()[0].name in ATTACKED_PUMPS for a in control.actions()):
            wn.remove_control(name)
            rule_name = name.replace(" ", "_")
            wn.add_control(rule_name, Rule(control.condition, control.actions(),
                                           priority=ControlPriority.medium, name=rule_name))
    return wn


def _window(n_steps: int, start_step: int, attack_steps: int, normal: float, attacked: float) -> list[float]:
    values = [normal] * n_steps
    for i in range(start_step, min(start_step + attack_steps, n_steps)):
        values[i] = attacked
    return values


def _run(scenario: str, attack_minutes: int, start_h: float, horizon_h: float, attack_dose: float):
    wn = _load()
    wn.options.time.duration = int(horizon_h * 3600)
    n_steps = int(horizon_h * 3600 // STEP_S) + 1
    start_step = int(start_h * 3600 // STEP_S)
    attack_steps = math.ceil(attack_minutes * 60 / STEP_S)

    if scenario == "dosing_setpoint_tamper":
        wn.options.quality.parameter = "CHEMICAL"
        wn.options.reaction.bulk_coeff = BULK_DECAY_PER_DAY / 86400
        wn.add_pattern("dose_pattern", _window(n_steps, start_step, attack_steps, 1.0, attack_dose / NORMAL_DOSE))
        for node in DOSING_NODES:
            wn.add_source(f"chlorinator_{node}", node, "SETPOINT", NORMAL_DOSE, "dose_pattern")
    elif attack_minutes > 0:
        t1, t2 = start_h * 3600, start_h * 3600 + attack_minutes * 60
        for pump in ATTACKED_PUMPS:
            cond = AndCondition(SimTimeCondition(wn, ">=", t1), SimTimeCondition(wn, "<", t2))
            action = ControlAction(wn.get_link(pump), "status", LinkStatus.Closed)
            wn.add_control(f"attack_{pump}", Rule(cond, [action], priority=ControlPriority.very_high,
                                                  name=f"attack_{pump}"))

    with warnings.catch_warnings(), tempfile.TemporaryDirectory() as tmp:
        warnings.simplefilter("ignore")
        results = wntr.sim.EpanetSimulator(wn).run_sim(file_prefix=str(Path(tmp) / "run"))
    demand_nodes = [n for n, j in wn.junctions() if j.demand_timeseries_list[0].base_value > 0]
    return results, demand_nodes, start_step


@lru_cache(maxsize=32)
def simulate_network(scenario: str, attack_minutes: int, start_h: float = 24, horizon_h: float = 96,
                     attack_dose: float = DOSE_MAX) -> NetworkImpact:
    if scenario not in HYDRAULIC_SCENARIOS:
        raise ValueError(f"no hydraulic model for {scenario!r}; choose from {HYDRAULIC_SCENARIOS}")
    results, nodes, start_step = _run(scenario, attack_minutes, start_h, horizon_h, attack_dose)
    base, _, _ = _run(scenario, 0, start_h, horizon_h, attack_dose)
    demand = results.node["demand"][nodes]

    if scenario == "dosing_setpoint_tamper":
        values = results.node["quality"][nodes]
        harmed = (values > CHLORINE_SAFE[1]) & ~(base.node["quality"][nodes] > CHLORINE_SAFE[1])
        volume = float((demand.clip(lower=0) * harmed).to_numpy().sum() * STEP_S)
        peak = float(values.iloc[start_step:].to_numpy().max())
    else:
        # zones cut off from every source return solver garbage (huge negative pressure or
        # demand); treat them as dry: zero pressure, nothing delivered
        values = results.node["pressure"][nodes].clip(lower=0)
        harmed = (values < MIN_SERVICE_PRESSURE) & ~(base.node["pressure"][nodes] < MIN_SERVICE_PRESSURE)
        expected = base.node["demand"][nodes].clip(lower=0)
        unserved = (expected - demand.clip(lower=0)).clip(lower=0).where(lambda u: u <= expected, expected)
        volume = float(unserved.to_numpy().sum() * STEP_S)
        peak = max(float(values.iloc[start_step:].to_numpy().min()), 0.0)  # 0 = zone ran dry

    after = harmed.iloc[start_step:]
    any_harm = after.any(axis=1).to_numpy()
    first = np.flatnonzero(any_harm)
    return NetworkImpact(
        scenario=scenario,
        attack_minutes=attack_minutes,
        nodes_affected=int(after.any(axis=0).sum()),
        demand_nodes=len(nodes),
        first_harm_h=round(float(first[0]) * STEP_S / 3600, 2) if len(first) else None,
        harm_hours=round(float(any_harm.sum()) * STEP_S / 3600, 2),
        harmful_volume_m3=round(volume, 1),
        peak_value=round(peak, 2),
        series_t_h=[round(t / 3600 - start_h, 2) for t in harmed.index],
        series_affected=harmed.sum(axis=1).astype(int).tolist(),
    )


def attack_minutes_from_control_sim(result: Result, cfg: SimConfig, uncontained_hours: float = 24) -> int:
    """Minutes the attacked actuator was actually in the attacker's state in the control-loop sim.

    If the attack was never contained inside the sim window, assume it keeps going until
    someone notices from outside the control system (default: 24 hours).
    """
    if result.scenario == "dosing_setpoint_tamper":
        attacked = [p["dose"] > 5.0 for p in result.trace]
    elif result.scenario == "plc_takeover":
        attacked = [p["pump"] < 1.0 for p in result.trace]
    else:
        raise ValueError(f"no hydraulic mapping for {result.scenario!r}")
    minutes = sum(attacked[cfg.attack_start:])
    if result.contained_after is None and minutes:
        return max(minutes, int(uncontained_hours * 60))
    return minutes


def impact_by_level(scenario: str, cfg: SimConfig | None = None, uncontained_hours: float = 24,
                    horizon_h: float = 96) -> dict[Maturity, NetworkImpact]:
    cfg = cfg or SimConfig()
    out = {}
    for level in Maturity:
        minutes = attack_minutes_from_control_sim(run(scenario, level, cfg), cfg, uncontained_hours)
        out[level] = simulate_network(scenario, minutes, horizon_h=horizon_h)
    return out
