"""Level 4 physics-based validation on BATADAL (paper Table I: "physics-based validation").

An ML detector only learns what normal data *looks like*, so an attacker can craft readings that
look normal. Physics checks instead test whether the readings *obey the network's laws*, taken from
the C-Town EPANET model rather than learned from data:

    status-flow   a pump or valve reported OFF must carry no flow, one reported ON must; status is 0/1
    pump-curve    for pumps with pressure sensors on both sides, the measured head gain must match
                  the manufacturer's pump curve at the measured flow

Only a per-pump offset and tolerance are calibrated on normal data, to absorb sensor bias.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import wntr

from .hydraulics import NETWORK, _load  # noqa: F401  (_load downloads the network if missing)

MIN_ON_FLOW = 5.0     # L/s: below this a running pump is implausible
MAX_OFF_FLOW = 1.0    # L/s: above this a stopped pump is implausible
STATUS_TOL = 0.05     # a status reading must be within this of 0 or 1


@dataclass
class PumpCurveCheck:
    pump: str
    start: str
    end: str
    dz: float                      # elevation gain, m
    curve: np.ndarray              # (flow m3/s, head m) points
    offset: float = 0.0
    tolerance: float = 1.5

    @property
    def sensors(self) -> list[str]:
        return [f"S_{self.pump}", f"F_{self.pump}", f"P_{self.start}", f"P_{self.end}"]

    def residual(self, df: pd.DataFrame) -> np.ndarray:
        gain = df[f"P_{self.end}"] - df[f"P_{self.start}"] + self.dz
        expected = np.interp(df[f"F_{self.pump}"] / 1000, self.curve[:, 0], self.curve[:, 1])
        return (gain - expected - self.offset).to_numpy()

    def expected_gain(self, flow: np.ndarray) -> np.ndarray:
        return np.interp(flow / 1000, self.curve[:, 0], self.curve[:, 1]) + self.offset - self.dz

    def violations(self, df: pd.DataFrame) -> np.ndarray:
        on = (df[f"S_{self.pump}"] > 0.5).to_numpy()
        return on & (np.abs(self.residual(df)) > self.tolerance)


@dataclass
class PhysicsValidator:
    links: list[str] = field(default_factory=list)            # pumps/valves with S_ and F_ sensors
    curves: list[PumpCurveCheck] = field(default_factory=list)

    def fit(self, normal: pd.DataFrame) -> "PhysicsValidator":
        if not NETWORK.exists():
            _load()   # downloads C-Town
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            wn = wntr.network.WaterNetworkModel(str(NETWORK))
        cols = set(normal.columns)
        self.links = [n for n in [*wn.pump_name_list, *wn.valve_name_list] if {f"S_{n}", f"F_{n}"} <= cols]
        self.curves = []
        for name in wn.pump_name_list:
            pump = wn.get_link(name)
            s, e = pump.start_node_name, pump.end_node_name
            if not {f"P_{s}", f"P_{e}"} <= cols:
                continue
            check = PumpCurveCheck(name, s, e, wn.get_node(e).elevation - wn.get_node(s).elevation,
                                   np.array(wn.get_curve(pump.pump_curve_name).points))
            on = normal[f"S_{name}"] > 0.5
            if on.sum() < 100:
                continue   # pump (almost) never runs in the normal year: nothing to calibrate against
            r = check.residual(normal[on])
            check.offset = float(np.median(r))
            check.tolerance = max(1.5, 1.5 * float(np.quantile(np.abs(r - check.offset), 0.999)))
            self.curves.append(check)
        return self

    def status_violations(self, df: pd.DataFrame, link: str) -> np.ndarray:
        s, f = df[f"S_{link}"].to_numpy(), df[f"F_{link}"].to_numpy()
        not_binary = np.minimum(np.abs(s), np.abs(s - 1)) > STATUS_TOL
        off_but_flowing = (s < 0.5) & (f > MAX_OFF_FLOW)
        on_but_dry = (s >= 0.5) & (f < MIN_ON_FLOW)
        return not_binary | off_but_flowing | on_but_dry

    def breakdown(self, df: pd.DataFrame) -> dict[str, np.ndarray]:
        out = {f"status-flow {n}": self.status_violations(df, n) for n in self.links}
        out.update({f"pump-curve {c.pump}": c.violations(df) for c in self.curves})
        return out

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return np.any(np.stack(list(self.breakdown(df).values())), axis=0)

    def repair(self, df: pd.DataFrame, controlled: set[str]) -> pd.DataFrame:
        """What a physics-aware attacker does to their forged readings: make every invariant hold,
        using only the sensors they control. Invariants that involve sensors they don't control
        stay as the honest sensors report them."""
        df = df.copy()
        for link in self.links:
            s, f = f"S_{link}", f"F_{link}"
            if s in controlled:
                df[s] = (df[s] > 0.5).astype(float)
            if f in controlled:
                on = df[s] > 0.5
                df.loc[~on, f] = 0.0
                df.loc[on, f] = df.loc[on, f].clip(lower=MIN_ON_FLOW)
            elif s in controlled:
                df[s] = (df[f] > MIN_ON_FLOW).astype(float)   # status must follow the honest flow
        for c in self.curves:
            gain = c.expected_gain(df[f"F_{c.pump}"].to_numpy())
            if f"P_{c.end}" in controlled:
                df[f"P_{c.end}"] = np.where(df[f"S_{c.pump}"] > 0.5, df[f"P_{c.start}"] + gain, df[f"P_{c.end}"])
            elif f"P_{c.start}" in controlled:
                df[f"P_{c.start}"] = np.where(df[f"S_{c.pump}"] > 0.5, df[f"P_{c.end}"] - gain, df[f"P_{c.start}"])
        return df


def sensor_groups(phys: PhysicsValidator, columns: list[str]) -> list[set[str]]:
    """Sensors bound together by one invariant; a careful forger must control a whole group."""
    groups, used = [], set()
    for c in phys.curves:
        groups.append(set(c.sensors))
        used |= set(c.sensors)
    for link in phys.links:
        g = {f"S_{link}", f"F_{link}"}
        if not g & used:
            groups.append(g)
            used |= g
    return groups + [{c} for c in columns if c not in used]


def physics_aware_evasion(det, phys: PhysicsValidator, X: np.ndarray, rows: np.ndarray, controlled: set[str],
                          rounds: int = 4) -> np.ndarray:
    """Alternate between fooling the ML detector and repairing the forged readings so every
    invariant the attacker can control still holds (projected gradient descent)."""
    from .ml import UNBOUNDED, pgd_evasion
    mask = np.array([c in controlled for c in det.columns])
    to_raw = lambda A: pd.DataFrame(A * det.std.to_numpy() + det.mean.to_numpy(), columns=det.columns)
    X_adv = X.copy()
    for _ in range(rounds):
        X_adv = pgd_evasion(det, X_adv, rows, UNBOUNDED, mask, steps=60)
        X_adv = det.transform(phys.repair(to_raw(X_adv), controlled))
        X_adv = np.where(mask, X_adv, X)   # honest sensors keep reporting the truth
    return X_adv


def best_groups(det, X: np.ndarray, rows: np.ndarray, groups: list[set[str]], k: int) -> set[str]:
    """Greedy: the attacker's most useful complete groups that fit in a budget of k sensors."""
    contrib = dict(zip(det.columns, np.mean(
        [((m.predict(X[rows]) - X[rows]) ** 2).mean(axis=0) for m in det.models], axis=0)))
    chosen: set[str] = set()
    for g in sorted(groups, key=lambda g: -sum(contrib[s] for s in g) / len(g)):
        if len(chosen) + len(g) <= k:
            chosen |= g
    return chosen
