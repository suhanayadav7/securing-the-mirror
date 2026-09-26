import numpy as np
import pytest

pytest.importorskip("sklearn")
from mirror import ml  # noqa: E402


@pytest.fixture(scope="module")
def trained():
    normal, attacked = ml.load()
    det = ml.Detector().fit(normal)
    X = det.transform(attacked)
    labels = (attacked["ATT_FLAG"] == 1).to_numpy()
    return det, X, labels


def test_attack_windows():
    labels = np.array([0, 1, 1, 0, 0, 1, 0, 1], bool)
    assert ml.attack_windows(labels) == [(1, 2), (5, 5), (7, 7)]


def test_gradient_matches_finite_differences(trained):
    det, X, labels = trained
    x = X[np.flatnonzero(labels)[:2]]
    eps = 1e-4
    numeric = np.zeros_like(x)
    for j in range(x.shape[1]):
        up, down = x.copy(), x.copy()
        up[:, j] += eps
        down[:, j] -= eps
        numeric[:, j] = (det.row_error(up) - det.row_error(down)) / (2 * eps)
    assert np.allclose(det.gradient(x), numeric, atol=1e-6)


def test_detector_finds_every_labelled_attack(trained):
    det, X, labels = trained
    m = ml.evaluate(det.predict(X), labels)
    assert m.attacks_detected == m.attacks_total == 5
    assert m.f1 > 0.45


def test_threshold_calibrated_on_normal_data(trained):
    det, X, labels = trained
    normal, _ = ml.load()
    flagged = det.predict(det.transform(normal)).mean()
    assert flagged < 0.02


def test_controlling_many_sensors_evades_detection(trained):
    det, X, labels = trained
    rows = np.flatnonzero(labels)
    mask = ml.most_influential(det, X, rows, 20)
    conceal = np.unique(np.concatenate([np.arange(max(s - det.window + 1, 0), e + 1)
                                        for s, e in ml.attack_windows(labels)]))
    evaded = ml.evaluate(det.predict(ml.pgd_evasion(det, X, conceal, ml.UNBOUNDED, mask, steps=60)), labels)
    clean = ml.evaluate(det.predict(X), labels)
    assert evaded.recall < 0.1 < clean.recall
