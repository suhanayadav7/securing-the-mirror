"""ML anomaly detection on the real BATADAL dataset, and adversarial evasion of it.

BATADAL (Taormina et al., 2018) is SCADA data from the C-Town water network: 43 sensors
(tank levels, pump/valve flows and status, junction pressures), hourly.

    dataset03  one year of normal operation          -> training / threshold calibration
    dataset04  six months with labelled attacks      -> evaluation

Caveat carried into every result: dataset04 is only *partially* labelled. Some attacks are
deliberately left unlabelled (ATT_FLAG = -999, same as normal), so the false-positive count
here is an upper bound and precision a lower bound.

The detector is an autoencoder ensemble (paper Sec. II-A: "the twin knows what the system
should be doing"). The evasion is a white-box projected-gradient attack on the sensor readings
(paper Sec. II-B, Homaei et al. "The Dark Side of Digital Twins").
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "batadal"
BASE_URL = "https://www.batadal.net/data/"
FILES = {"normal": "BATADAL_dataset03.csv", "attacks": "BATADAL_dataset04.csv"}


def ensure_data(data_dir: Path = DATA_DIR) -> dict[str, Path]:
    """Download the BATADAL CSVs on first use (they are not redistributed with this repo)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for key, name in FILES.items():
        path = data_dir / name
        if not path.exists():
            urllib.request.urlretrieve(BASE_URL + name, path)
        paths[key] = path
    return paths


def load(data_dir: Path = DATA_DIR) -> tuple[pd.DataFrame, pd.DataFrame]:
    frames = []
    for path in ensure_data(data_dir).values():
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        df["DATETIME"] = pd.to_datetime(df["DATETIME"], format="%d/%m/%y %H")
        frames.append(df)
    return frames[0], frames[1]


def sensor_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in ("DATETIME", "ATT_FLAG")]


def attack_windows(labels: np.ndarray) -> list[tuple[int, int]]:
    """(start, end) row indices, inclusive, of each contiguous labelled attack."""
    windows, start = [], None
    for i, flag in enumerate(labels):
        if flag and start is None:
            start = i
        elif not flag and start is not None:
            windows.append((start, i - 1))
            start = None
    if start is not None:
        windows.append((start, len(labels) - 1))
    return windows


class Detector:
    """Ensemble of small autoencoders; anomaly score = smoothed reconstruction error."""

    def __init__(self, hidden=(24, 12, 24), seeds=(0, 2, 4), window=6, quantile=0.995) -> None:
        self.hidden, self.seeds, self.window, self.quantile = hidden, seeds, window, quantile

    def fit(self, normal: pd.DataFrame, holdout: float = 0.2) -> "Detector":
        self.columns = sensor_columns(normal)
        self.mean = normal[self.columns].mean()
        self.std = normal[self.columns].std().replace(0, 1)
        X = self.transform(normal)
        n = int(len(X) * (1 - holdout))
        self.models = [
            MLPRegressor(hidden_layer_sizes=self.hidden, max_iter=400, early_stopping=True, random_state=s).fit(
                X[:n], X[:n])
            for s in self.seeds
        ]
        # threshold calibrated on held-out *normal* data only
        self.threshold = float(np.quantile(self.score(X[n:]), self.quantile))
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        return ((df[self.columns] - self.mean) / self.std).to_numpy()

    def row_error(self, X: np.ndarray) -> np.ndarray:
        return np.mean([((m.predict(X) - X) ** 2).mean(axis=1) for m in self.models], axis=0)

    def score(self, X: np.ndarray) -> np.ndarray:
        return pd.Series(self.row_error(X)).rolling(self.window, min_periods=1).mean().to_numpy()

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.score(X) > self.threshold

    def gradient(self, X: np.ndarray) -> np.ndarray:
        """d(row reconstruction error)/dX, averaged over the ensemble (ReLU MLP, identity output)."""
        grad = np.zeros_like(X)
        d = X.shape[1]
        for m in self.models:
            activations, pre = [X], []
            for i, (W, b) in enumerate(zip(m.coefs_, m.intercepts_)):
                z = activations[-1] @ W + b
                pre.append(z)
                activations.append(z if i == len(m.coefs_) - 1 else np.maximum(z, 0))
            resid = activations[-1] - X
            g = 2 * resid / d
            for i in range(len(m.coefs_) - 1, -1, -1):
                g = g @ m.coefs_[i].T
                if i > 0:
                    g = g * (pre[i - 1] > 0)
            grad += g - 2 * resid / d
        return grad / len(self.models)


@dataclass
class Metrics:
    precision: float
    recall: float
    f1: float
    attacks_detected: int
    attacks_total: int
    mean_delay_h: float | None
    false_positive_hours: int
    delays_h: list[int | None]

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def evaluate(pred: np.ndarray, labels: np.ndarray) -> Metrics:
    tp = int((pred & labels).sum())
    fp = int((pred & ~labels).sum())
    fn = int((~pred & labels).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    delays = []
    for start, end in attack_windows(labels):
        hits = np.flatnonzero(pred[start:end + 1])
        delays.append(int(hits[0]) if len(hits) else None)
    found = [d for d in delays if d is not None]
    return Metrics(round(precision, 3), round(recall, 3), round(f1, 3), len(found), len(delays),
                   round(float(np.mean(found)), 1) if found else None, fp, delays)


UNBOUNDED = 100.0  # in std units: the attacker can write any plausible value to a sensor they control


def pgd_evasion(det: Detector, X: np.ndarray, rows: np.ndarray, epsilon: float,
                mask: np.ndarray | None = None, steps: int = 40) -> np.ndarray:
    """Perturb readings in `rows` (within +/- epsilon std, only features in `mask`) to hide them."""
    X_adv = X.copy()
    if epsilon <= 0:
        return X_adv
    mask = np.ones(X.shape[1], bool) if mask is None else mask
    base = X[rows]
    # start by pulling controlled sensors toward what the detector expects (its reconstruction)
    recon = np.mean([m.predict(base) for m in det.models], axis=0)
    delta = np.clip((recon - base) * mask, -epsilon, epsilon)
    for i in range(steps):
        step = epsilon / 4 * (1 - i / steps) + 1e-3
        g = det.gradient(base + delta)
        delta = np.clip(delta - step * np.sign(g) * mask, -epsilon, epsilon)
    X_adv[rows] = base + delta
    return X_adv


def replay_evasion(X: np.ndarray, rows: np.ndarray, lag: int = 168) -> np.ndarray:
    """Replace readings during the attack with the same hour one week earlier (all sensors)."""
    X_adv = X.copy()
    src = np.clip(rows - lag, 0, None)
    X_adv[rows] = X[src]
    return X_adv


def most_influential(det: Detector, X: np.ndarray, rows: np.ndarray, k: int) -> np.ndarray:
    """Mask of the k sensors that contribute most reconstruction error during the attacks -
    the ones an attacker controlling only k signed-out sensors would pick."""
    contrib = np.mean([((m.predict(X[rows]) - X[rows]) ** 2).mean(axis=0) for m in det.models], axis=0)
    mask = np.zeros(X.shape[1], bool)
    mask[np.argsort(contrib)[-k:]] = True
    return mask


def run_experiment(sensor_counts=(0, 1, 3, 5, 10, 20, 43)) -> dict:
    """Train, evaluate, then attack the detector. Returns a JSON-serialisable result dict.

    The adaptive attacker fully controls the readings of k sensors (the k most useful to them)
    and optimises those readings against the detector. With plaintext telemetry (Levels 1-3) an
    attacker on the network can rewrite any number of readings; with signed packets (Level 4)
    only sensors they physically tamper with, so k stays small.
    """
    normal, attacked = load()
    det = Detector().fit(normal)
    X = det.transform(attacked)
    labels = (attacked["ATT_FLAG"] == 1).to_numpy()
    rows = np.flatnonzero(labels)
    # the attacker starts concealing a few hours before acting, so the smoothing window
    # cannot carry pre-attack evidence into the attack
    conceal = np.unique(np.concatenate([np.arange(max(s - det.window + 1, 0), e + 1)
                                        for s, e in attack_windows(labels)]))

    clean = evaluate(det.predict(X), labels)
    # per-seed spread, so a single lucky seed is not reported as the result
    singles = []
    for s in (0, 1, 2, 3, 4):
        d = Detector(seeds=(s,)).fit(normal)
        singles.append(evaluate(d.predict(d.transform(attacked)), labels).f1)

    curve = []
    for k in sensor_counts:
        if k == 0:
            m = clean
        else:
            mask = most_influential(det, X, rows, k)
            m = evaluate(det.predict(pgd_evasion(det, X, conceal, UNBOUNDED, mask, steps=100)), labels)
        curve.append({"sensors_controlled": k, "recall": m.recall, "attacks_detected": m.attacks_detected})
    replay = evaluate(det.predict(replay_evasion(X, conceal)), labels)

    return {
        "dataset": {"train_hours": len(normal), "eval_hours": len(attacked), "attack_hours": int(labels.sum()),
                    "labelled_attacks": len(attack_windows(labels)), "sensors": len(det.columns)},
        "threshold": det.threshold,
        "clean": clean.as_dict(),
        "single_seed_f1": singles,
        "adversarial": curve,
        "top_sensors": [c for c, m in zip(det.columns, most_influential(det, X, rows, 5)) if m],
        "replay": replay.as_dict(),
        "attack_start": [str(attacked["DATETIME"].iloc[s]) for s, _ in attack_windows(labels)],
        "score": det.score(X).round(4).tolist(),
        "labels": labels.astype(int).tolist(),
        "time": attacked["DATETIME"].dt.strftime("%Y-%m-%d %H:%M").tolist(),
    }
