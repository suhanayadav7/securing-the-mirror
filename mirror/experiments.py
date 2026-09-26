"""End-semester experiment: do an LSTM and Level 4 physics checks close the gap the
autoencoder leaves open? Results are saved to results/defenses.json for the dashboard."""

from __future__ import annotations

import numpy as np
import pandas as pd

from .ml import (UNBOUNDED, Detector, attack_windows, evaluate, load, most_influential, pgd_evasion,
                 replay_evasion)
from .physics import PhysicsValidator, best_groups, physics_aware_evasion, sensor_groups

SENSOR_COUNTS = (0, 5, 10, 20, 43)


def _conceal(labels: np.ndarray, lead: int) -> np.ndarray:
    return np.unique(np.concatenate([np.arange(max(s - lead, 0), e + 1) for s, e in attack_windows(labels)]))


def run_defenses(lstm: bool = True, lstm_seeds=(0, 1, 2), log=print) -> dict:
    normal, attacked = load()
    labels = (attacked["ATT_FLAG"] == 1).to_numpy()
    rows = np.flatnonzero(labels)
    out: dict = {"sensor_counts": list(SENSOR_COUNTS)}

    # --- autoencoder + physics ----------------------------------------------------------------
    ae = Detector().fit(normal)
    X = ae.transform(attacked)
    phys = PhysicsValidator().fit(normal)
    raw = lambda A: pd.DataFrame(A * ae.std.to_numpy() + ae.mean.to_numpy(), columns=ae.columns)
    conceal = _conceal(labels, ae.window - 1)
    p_clean = phys.predict(attacked)

    out["physics"] = {
        "invariants": list(phys.breakdown(attacked)),
        "sensors_covered": len(set().union(*[g for g in sensor_groups(phys, ae.columns) if len(g) > 1])),
        "normal_false_alarm_rate": round(float(phys.predict(normal).mean()), 5),
        "clean": evaluate(p_clean, labels).as_dict(),
        "curves": [{"pump": c.pump, "offset_m": round(c.offset, 2), "tolerance_m": round(c.tolerance, 2)}
                   for c in phys.curves],
    }
    out["autoencoder"] = {"clean": evaluate(ae.predict(X), labels).as_dict(),
                          "clean_with_physics": evaluate(ae.predict(X) | p_clean, labels).as_dict()}
    log("autoencoder + physics: clean done")

    groups = sensor_groups(phys, ae.columns)
    curve = []
    for k in SENSOR_COUNTS:
        if k == 0:
            a = ae.predict(X)
            row = {"k": 0, "ae": evaluate(a, labels), "ae_phys_naive": evaluate(a | p_clean, labels),
                   "ae_phys_aware": evaluate(a | p_clean, labels)}
        else:
            X_naive = pgd_evasion(ae, X, conceal, UNBOUNDED, most_influential(ae, X, rows, k), steps=100)
            a_naive = ae.predict(X_naive)
            X_aware = physics_aware_evasion(ae, phys, X, conceal, best_groups(ae, X, rows, groups, k))
            row = {"k": k, "ae": evaluate(a_naive, labels),
                   "ae_phys_naive": evaluate(a_naive | phys.predict(raw(X_naive)), labels),
                   "ae_phys_aware": evaluate(ae.predict(X_aware) | phys.predict(raw(X_aware)), labels)}
        curve.append({"k": row["k"], **{f"{name}_recall": m.recall for name, m in row.items() if name != "k"},
                      **{f"{name}_attacks": m.attacks_detected for name, m in row.items() if name != "k"}})
        log(f"autoencoder evasion k={k} done")
    out["autoencoder"]["evasion"] = curve
    out["autoencoder"]["replay"] = evaluate(ae.predict(replay_evasion(X, conceal)), labels).as_dict()

    # --- LSTM ---------------------------------------------------------------------------------
    if lstm:
        from .lstm import LSTMDetector
        seeds = []
        for s in lstm_seeds:
            det = LSTMDetector(seed=s).fit(normal)
            seeds.append(evaluate(det.predict(det.transform(attacked)), labels).as_dict())
            log(f"LSTM seed {s} trained")
        det = LSTMDetector(seed=lstm_seeds[0]).fit(normal)
        XL = det.transform(attacked)
        conceal_l = _conceal(labels, det.window + det.seq_len - 1)
        lcurve = []
        for k in SENSOR_COUNTS:
            if k == 0:
                m = evaluate(det.predict(XL), labels)
            else:
                m = evaluate(det.predict(det.evade(XL, conceal_l, det.most_influential(XL, rows, k), steps=150)),
                             labels)
            lcurve.append({"k": k, "recall": m.recall, "attacks": m.attacks_detected})
            log(f"LSTM evasion k={k} done")
        out["lstm"] = {"seeds": seeds, "clean": seeds[0], "evasion": lcurve,
                       "replay": evaluate(det.predict(replay_evasion(XL, conceal_l)), labels).as_dict()}
    return out
