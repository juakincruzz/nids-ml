"""El clasificador aprende la limpieza de train y el umbral de validación, nada más."""

import numpy as np
import pandas as pd
import pytest

from nids.evaluation.metrics import choose_threshold
from nids.models.classifiers import FlowClassifier, make_lightgbm, make_logistic


def _synthetic(n, seed, attack_rate=0.2):
    """Flujos sintéticos: los ataques tienen más paquetes y son más cortos."""
    rng = np.random.default_rng(seed)
    is_attack = rng.random(n) < attack_rate
    return pd.DataFrame(
        {
            "Flow Duration": np.where(is_attack, rng.normal(10, 3, n), rng.normal(50, 10, n)),
            "Total Fwd Packet": np.where(is_attack, rng.normal(80, 10, n), rng.normal(20, 10, n)),
            "Dst Port": np.where(is_attack, 80, rng.choice([80, 443, 53], n)).astype(float),
            "family": np.where(is_attack, "dos", "benign"),
            "is_attack": is_attack,
        }
    )


@pytest.fixture
def train_val():
    train, validation = _synthetic(400, 1), _synthetic(200, 2)
    train.loc[0, "Flow Duration"] = np.nan  # para que la mediana importe
    return train, validation


@pytest.mark.parametrize(
    "estimator",
    [make_lightgbm({"n_estimators": 20, "min_child_samples": 5}, seed=0), make_logistic(seed=0)],
)
def test_limpieza_de_train_y_umbral_de_validacion(train_val, estimator):
    train, validation = train_val
    clf = FlowClassifier("x", estimator).fit(train, validation, 1.0, 5)

    # Medianas de train, no de train + validación.
    assert clf.cleaner_.medians_["Flow Duration"] == train["Flow Duration"].median()

    # El umbral es exactamente el de las puntuaciones de validación con el presupuesto.
    val_score = clf.attack_score(validation)
    expected = choose_threshold(validation["is_attack"], val_score, 1.0, 5)
    assert clf.threshold_ == expected
    assert np.sum((val_score > clf.threshold_) & ~validation["is_attack"]) <= 5


def test_prediccion_da_puntuacion_marca_y_familia(train_val):
    train, validation = train_val
    clf = FlowClassifier("x", make_logistic(seed=0)).fit(train, validation, 1.0, 5)
    score, flagged, family = clf.predict(validation)
    assert np.isfinite(score).all()
    assert set(family[flagged]) <= {"dos"}
    assert set(family[~flagged]) == {"benign"}
    # Es separable: casi todos los ataques se detectan.
    assert flagged[validation["is_attack"]].mean() > 0.9


def test_la_puntuacion_no_se_satura_con_logits_extremos():
    # Con 1 − P(normal) estos dos flujos empatarían en 1,0; con log-odds no.
    clf = FlowClassifier("x", None)
    clf.classes_ = ["benign", "dos", "scan"]
    logits = np.array([[0.0, 50.0, -10.0], [0.0, 60.0, -10.0], [5.0, 0.0, 0.0]])
    score = clf.attack_score(None, logits)
    assert score[1] > score[0] > 0 > score[2]
    assert score[0] == pytest.approx(50.0)
    # Benigno con logit 5 frente a dos ataques con 0: log(2) − 5.
    assert score[2] == pytest.approx(np.log(2) - 5)
