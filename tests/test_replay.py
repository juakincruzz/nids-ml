"""Motor de reproducción: incidentes, marcador y eventos, con casos calculados a mano."""

import numpy as np
import pandas as pd
import pytest

from nids.replay.engine import DayReplay, group_incidents

START = pd.Timestamp("2017-07-07 18:50", tz="UTC").timestamp()  # 15:50 en el laboratorio


def make_flows(rows):
    """rows: (segundos desde START, src, dst, familia, ¿marca el modelo?, su familia, reglas)."""
    df = pd.DataFrame(
        rows, columns=["dt", "src_ip", "dst_ip", "family", "model_flagged", "model_family", "rules"]
    )
    df["t"] = START + df.pop("dt").astype(float)
    df["is_attack"] = df["family"] != "benign"
    df["label"] = np.where(df["is_attack"], "DDoS", "BENIGN")
    df["model_score"] = np.linspace(-5, 5, len(df))
    df["rules_flagged"] = df.pop("rules")
    df["rules_family"] = np.where(df["rules_flagged"], "dos", "benign")
    for rule in ("scan", "brute_force", "dos"):
        df[f"rule_{rule}"] = 0.0
    df["Dst Port"] = 80.0
    return df.sort_values("t").reset_index(drop=True)


@pytest.fixture
def flows():
    return make_flows(
        [
            (0, "a", "v", "benign", False, "benign", False),
            (10, "x", "v", "dos", True, "dos", True),
            (20, "x", "v", "dos", True, "dos", True),
            (30, "x", "v", "dos", True, "dos", False),
            (40, "b", "w", "benign", True, "scan", False),  # falsa alarma del modelo
            (200, "x", "v", "dos", True, "dos", False),  # hueco > 60 s: incidente nuevo
            (300, "c", "w", "benign", False, "benign", False),
        ]
    )


def test_agrupa_en_incidentes_por_origen_destino_familia_y_hueco(flows):
    incidents = group_incidents(flows, "model")
    summary = [(i.src_ip, i.family, len(i.times), i.start - START) for i in incidents]
    assert summary == [("x", "dos", 3, 10), ("b", "scan", 1, 40), ("x", "dos", 1, 200)]
    assert [i.id for i in incidents] == [0, 1, 2]
    # Representativo: el de mayor puntuación (las puntuaciones crecen con la fila).
    assert incidents[0].rep == 3
    assert incidents[0].n_attack == 3 and incidents[1].n_attack == 0
    assert 0 < incidents[0].confidence < 1


def test_snapshot_y_eventos(flows):
    replay = DayReplay("friday", flows)
    # Modelo: 3 incidentes; reglas: 1 (flujos de t=10 y t=20).
    assert len(replay.incidents) == 4

    assert [inc.id for inc in replay.incidents] == [0, 1, 2, 3]  # id = posición

    shot = replay.snapshot(START + 25)
    assert [(inc.source, n) for inc, n in shot] == [("model", 2), ("rules", 2)]

    new, updates = replay.events_between(START + 25, START + 45)
    assert [(inc.source, inc.family) for inc in new] == [("model", "scan")]
    # El incidente de DoS del modelo pasa de 2 a 3 flujos; el de las reglas ya no crece.
    assert [(inc.source, n) for inc, n in updates] == [("model", 3)]


def test_marcador_calculado_a_mano(flows):
    replay = DayReplay("friday", flows)
    s = replay.scoreboard(START + 45)
    # Hasta t=45: 5 flujos, 3 ataques; el modelo detecta los 3 y marca 1 normal; reglas 2 de 3.
    assert (s["flows"], s["attacks"]) == (5, 3)
    assert s["model"]["detected"] == 3 and s["model"]["false_alarms"] == 1
    assert s["model"]["recall"] == 1.0
    assert s["rules"]["recall"] == pytest.approx(2 / 3)
    # Con menos de un minuto transcurrido no se da tasa...
    assert s["model"]["false_alarms_per_hour"] is None
    # ...y a los 100 s: 1 falsa alarma en 100 s = 36 por hora.
    assert replay.scoreboard(START + 100)["model"]["false_alarms_per_hour"] == pytest.approx(36)


def test_linea_temporal_y_zonas(flows):
    tl = DayReplay("friday", flows).timeline(bin_seconds=5)
    assert len(tl["flows_per_second"]) == 60  # 300 s en intervalos de 5 s
    assert sum(tl["model_alerts"]) == 5 and sum(tl["rules_alerts"]) == 2
    # DoS en t=10-30 y en t=200: el hueco (34 intervalos) supera el máximo (30) y quedan dos.
    assert [(z["family"], z["start"] - START, z["end"] - START) for z in tl["zones"]] == [
        ("dos", 10, 35),
        ("dos", 200, 205),
    ]
