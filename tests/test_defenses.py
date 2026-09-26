import numpy as np
import pandas as pd
import pytest

pytest.importorskip("wntr")
from mirror import ml  # noqa: E402
from mirror.physics import PhysicsValidator, sensor_groups  # noqa: E402


@pytest.fixture(scope="module")
def setup():
    normal, attacked = ml.load()
    return normal, attacked, PhysicsValidator().fit(normal)


def test_physics_rarely_alarms_on_normal_data(setup):
    normal, _, phys = setup
    assert phys.predict(normal).mean() < 0.005


def test_physics_invariants_come_from_the_network_model(setup):
    _, _, phys = setup
    assert len(phys.links) == 12                            # 11 pumps + valve V2
    assert {c.pump for c in phys.curves} == {"PU2", "PU10"}  # pumps with pressure on both sides


def test_impossible_forgeries_are_caught(setup):
    normal, _, phys = setup
    df = normal.head(50).copy()
    df["S_PU7"] = 0.4                                        # half-on pump
    assert phys.predict(df).all()
    df = normal.head(50).copy()
    on = df["S_PU2"] > 0.5
    df.loc[on, "P_J269"] += 10                               # pump head off its curve
    assert phys.predict(df)[on.to_numpy()].all()


def test_repair_satisfies_invariants_for_fully_controlled_groups(setup):
    normal, _, phys = setup
    df = normal.head(200).copy()
    df["S_PU7"], df["F_PU7"] = 0.4, 3.0
    group = {"S_PU2", "F_PU2", "P_J280", "P_J269"}
    df["P_J269"] += 7
    fixed = phys.repair(df, {"S_PU7", "F_PU7", *group})
    assert not phys.predict(fixed).any()


def test_groups_partition_the_sensors(setup):
    normal, _, phys = setup
    cols = ml.sensor_columns(normal)
    groups = sensor_groups(phys, cols)
    assert sorted(s for g in groups for s in g) == sorted(cols)


def test_lstm_trains_and_scores():
    pytest.importorskip("torch")
    from mirror.lstm import LSTMDetector
    normal, attacked = ml.load()
    det = LSTMDetector(epochs=2, seq_len=12).fit(normal.head(2000))
    X = det.transform(attacked.head(300))
    assert det.score(X).shape == (300,)
    rows = np.arange(100, 140)
    before = det.row_error(X)[rows].mean()
    after = det.row_error(det.evade(X, rows, np.ones(X.shape[1], bool), steps=30))[rows].mean()
    assert after < before
