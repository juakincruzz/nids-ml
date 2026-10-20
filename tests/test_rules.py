"""Reglas de umbral con flujos hechos a mano."""

import numpy as np
import pandas as pd
import pytest

from nids.models.rules import apply_rules, rule_scores, tune_thresholds


def _flow(t, src, dst, port, duration_s=1.0, packets=2, is_attack=False):
    return {
        "timestamp": pd.Timestamp("2017-07-03 12:00", tz="UTC") + pd.Timedelta(seconds=t),
        "src_ip": src,
        "dst_ip": dst,
        "Dst Port": port,
        "Flow Duration": duration_s * 1e6,
        "Total Fwd Packet": packets // 2,
        "Total Bwd packets": packets - packets // 2,
        "is_attack": is_attack,
    }


@pytest.fixture
def flows():
    rows = []
    # Escáner: 10 puertos distintos en 10 s.
    rows += [_flow(i, "10.0.0.1", "10.0.0.9", 1000 + i, is_attack=True) for i in range(10)]
    # Normal: 2 conexiones a la web.
    rows += [_flow(i, "10.0.0.2", "10.0.0.9", 443) for i in range(2)]
    # Fuerza bruta: 5 intentos cortos a SSH + una sesión SSH larga del mismo origen.
    rows += [_flow(i, "10.0.0.3", "10.0.0.9", 22, duration_s=10, is_attack=True) for i in range(5)]
    rows.append(_flow(30, "10.0.0.3", "10.0.0.9", 22, duration_s=600))
    # DoS: 600 paquetes en un solo flujo hacia un destino (10 paquetes/s en 60 s).
    rows.append(_flow(5, "10.0.0.4", "10.0.0.8", 80, packets=600, is_attack=True))
    # Un flujo en la ventana siguiente del escáner: ya no cuenta con los anteriores.
    rows.append(_flow(65, "10.0.0.1", "10.0.0.9", 443))
    return pd.DataFrame(rows)


@pytest.fixture
def scores(flows):
    return rule_scores(
        flows, window_seconds=60, brute_force_ports=[21, 22], brute_force_max_duration_seconds=30
    )


def test_estadisticos(flows, scores):
    assert scores["scan"].iloc[0] == 10  # escáner
    assert scores["scan"].iloc[10] == 1  # normal
    assert scores["scan"].iloc[-1] == 1  # otra ventana
    # Las 5 conexiones cortas cuentan 5; la sesión larga no es «corta» y queda en 0.
    assert list(scores["brute_force"].iloc[12:17]) == [5] * 5
    assert scores["brute_force"].iloc[17] == 0
    assert scores["dos"].iloc[18] == pytest.approx(10.0)
    assert scores["dos"].iloc[10] == pytest.approx(4 / 60)  # 2 flujos de 2 paquetes


def test_aplicar_reglas(scores):
    flagged, family = apply_rules(scores, {"scan": 5, "brute_force": 3, "dos": 5})
    assert flagged[:10].all() and set(family[:10]) == {"scan"}
    assert not flagged[10:12].any()
    assert flagged[12:17].all() and set(family[12:17]) == {"brute_force"}
    assert flagged[18] and family[18] == "dos"
    assert family[11] == "benign"


def test_ajuste_con_presupuesto_cero_no_marca_normales(flows, scores):
    thresholds = tune_thresholds(scores, flows["is_attack"], hours=1, max_false_alarms_per_hour=0)
    flagged, _ = apply_rules(scores, thresholds)
    assert not np.any(flagged & ~flows["is_attack"].to_numpy())
    # Y aun así detecta el escaneo y la fuerza bruta.
    assert flagged[:10].all() and flagged[12:17].all()
