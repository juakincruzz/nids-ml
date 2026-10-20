"""Explicaciones: diccionario de frases, SHAP exacto y referencia de «lo normal» de train."""

import numpy as np
import pandas as pd
import pytest

from nids.data.clean import load_raw_day
from nids.explain.explainer import AlertExplainer
from nids.explain.phrases import FEATURES, describe, format_value
from nids.features.columns import feature_columns
from nids.models.classifiers import FlowClassifier, make_lightgbm


def test_todas_las_variables_reales_tienen_frase(raw_sample_path):
    df, _ = load_raw_day(raw_sample_path, "monday")
    missing = [f for f in feature_columns(df) if f not in FEATURES]
    assert missing == []


@pytest.mark.parametrize(
    ("value", "unit", "text"),
    [
        (1_500_000, "us", "1,5 s"),
        (2_500, "us", "2,5 ms"),
        (40, "us", "40 µs"),
        (1_234_567, "B/s", "1,2 MB/s"),
        (512, "B", "512 B"),
        (22, "port", "22 (SSH)"),
        (6, "proto", "TCP"),
        (1004, "count", "1 004"),
    ],
)
def test_formato_de_valores(value, unit, text):
    assert format_value(value, unit) == text


def test_la_frase_depende_de_si_esta_por_encima_o_por_debajo():
    assert describe("Flow Packets/s", 5000, normal=10) == "envía paquetes muy deprisa"
    assert describe("Flow Packets/s", 1, normal=10) == "envía paquetes muy despacio"
    assert describe("Dst Port", 22, normal=443) == "puerto de destino"


@pytest.fixture(scope="module")
def trained():
    """Modelo pequeño con tres clases: el escaneo toca puertos raros, el DoS envía muchísimo."""
    rng = np.random.default_rng(0)
    n = 600
    family = rng.choice(["benign", "dos", "scan"], n, p=[0.6, 0.2, 0.2])
    df = pd.DataFrame(
        {
            "Flow Packets/s": np.where(family == "dos", 5000.0, 10.0) * rng.uniform(0.5, 1.5, n),
            "Dst Port": np.where(family == "scan", rng.integers(1000, 9000, n), 443).astype(float),
            "Flow Duration": rng.normal(1e6, 1e5, n),
            "family": family,
            "is_attack": family != "benign",
        }
    )
    train, validation = df.iloc[:400], df.iloc[400:]
    clf = FlowClassifier(
        "x", make_lightgbm({"n_estimators": 30, "min_child_samples": 5}, seed=0)
    ).fit(train, validation, 1.0, 5)
    return clf, train, validation


def test_lo_normal_es_la_mediana_del_trafico_normal_de_train(trained):
    clf, train, _ = trained
    benign = train[~train["is_attack"]]
    assert clf.benign_medians_["Flow Packets/s"] == pytest.approx(benign["Flow Packets/s"].median())


def test_shap_suma_exactamente_la_diferencia_de_logits(trained):
    clf, _, validation = trained
    explainer = AlertExplainer(clf, {"scan": 100, "brute_force": 3, "dos": 1000})
    X = clf.cleaner_.transform(validation)
    dos = clf.classes_.index("dos")
    contrib = explainer.contributions(X, np.full(len(X), dos))

    z = clf.logits(validation)
    base = explainer.tree.expected_value
    expected = z[:, dos] - z[:, explainer.benign] - (base[dos] - base[explainer.benign])
    np.testing.assert_allclose(contrib.sum(axis=1), expected, rtol=1e-5, atol=1e-5)


def test_explicacion_de_una_alerta_de_dos(trained):
    clf, _, validation = trained
    explainer = AlertExplainer(clf, {"scan": 100, "brute_force": 3, "dos": 1000})
    row = validation[validation["family"] == "dos"].iloc[[0]]
    stats = pd.DataFrame({"scan": [1.0], "brute_force": [0.0], "dos": [4000.0]})
    [exp] = explainer.explain(row, stats)

    assert exp["family"] == "dos"
    assert exp["reasons"][0]["feature"] == "Flow Packets/s"
    assert exp["reasons"][0]["text"] == "envía paquetes muy deprisa"
    assert len(exp["reasons"]) == 3
    assert exp["rules"]["would_detect"]
    assert [d["fired"] for d in exp["rules"]["detail"]] == [False, False, True]
