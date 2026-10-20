"""Protocolo «ataques nuevos»: la familia excluida no llega a train y las métricas cuadran."""

import numpy as np
import pandas as pd
import pytest

from nids.evaluation.novel_attacks import family_result
from nids.evaluation.split import TEST, fit_and_threshold_sets, temporal_split
from nids.models.anomaly import AnomalyDetector


@pytest.fixture
def flows():
    """Un día de 300 flujos, uno por segundo, con familias repartidas por todo el día."""
    rng = np.random.default_rng(0)
    family = np.array(["benign"] * 240 + ["scan"] * 30 + ["dos"] * 30)
    rng.shuffle(family)
    return pd.DataFrame(
        {
            "timestamp": pd.date_range("2017-07-07 12:00", periods=300, freq="1s", tz="UTC"),
            "day": "friday",
            "family": family,
            "is_attack": family != "benign",
            "Flow Duration": rng.normal(100, 10, 300),
            "Total Fwd Packet": rng.normal(10, 2, 300),
        }
    )


def test_la_familia_excluida_no_aparece_en_train(flows):
    part = temporal_split(flows, 0.7, 0.2)
    fit, threshold = fit_and_threshold_sets(flows, part, exclude_family="scan")

    assert "scan" not in set(fit["family"])
    assert "dos" in set(fit["family"])  # las demás familias sí
    assert not threshold["is_attack"].any()
    assert not (part[fit.index] == TEST).any()


def test_family_result_calculado_a_mano():
    family = np.array(["scan", "scan", "scan", "scan", "dos", "benign", "benign", "benign"])
    is_benign = family == "benign"
    flagged = np.array([1, 1, 1, 0, 1, 1, 0, 0], bool)
    score = np.array([0.9, 0.8, 0.7, 0.1, 0.5, 0.6, 0.2, 0.3])
    r = family_result("scan", family, is_benign, flagged, hours=0.5, score=score)

    assert r["n_flows"] == 4 and r["detected"] == 3
    assert r["recall"] == 0.75
    # Un flujo normal marcado en media hora = 2 por hora (el DoS marcado no cuenta).
    assert r["false_alarms_per_hour"] == 2.0
    # Solo escaneo frente a normal: 4 de 7 flujos.
    assert r["prevalence"] == pytest.approx(4 / 7)
    # Orden: scan .9 .8 .7, normal .6, normal .3 .2, scan .1 -> AP = (1+1+1+4/7)/4.
    assert r["pr_auc"] == pytest.approx((3 + 4 / 7) / 4)


def test_el_detector_de_anomalias_solo_acepta_trafico_normal(flows):
    detector = AnomalyDetector(n_estimators=10, max_samples=32, seed=0, n_jobs=1)
    benign = flows[~flows["is_attack"]]
    with pytest.raises(ValueError, match="solo admite tráfico normal"):
        detector.fit(flows, benign, 1.0, 5)

    detector.fit(benign.iloc[:150], benign.iloc[150:], 1.0, 5)
    score, flagged = detector.predict(benign.iloc[150:])
    assert np.sum(flagged) <= 5  # respeta el presupuesto en su propia validación
    assert np.isfinite(score).all()
