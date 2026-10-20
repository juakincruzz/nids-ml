"""Rutas del panel con una reproducción sintética (sin modelo ni datos reales)."""

import json

import pytest
from fastapi.testclient import TestClient

from nids.config import load_config
from nids.replay.engine import DayReplay
from nids.web.app import create_app
from tests.test_replay import START, make_flows


class FakeExplainer:
    def explain(self, flows, stats):
        return [
            {
                "family": "dos",
                "is_alert": True,
                "confidence": 0.97,
                "reasons": [
                    {
                        "feature": "Flow Packets/s",
                        "text": "envía paquetes muy deprisa",
                        "value": "5 000 paquetes/s",
                        "normal": "10 paquetes/s",
                        "contribution": 3.2,
                    }
                ],
                "rules": {"would_detect": False, "detail": []},
            }
            for _ in range(len(flows))
        ]


@pytest.fixture
def client():
    flows = make_flows(
        [
            (0, "a", "v", "benign", False, "benign", False),
            (60, "x", "v", "dos", True, "dos", True),
            (90, "x", "v", "dos", True, "dos", True),
            (150, "b", "w", "benign", True, "scan", False),
            (240, "c", "w", "benign", False, "benign", False),
        ]
    )
    replay = DayReplay("friday", flows)
    app = create_app(load_config(), replays=lambda day: replay, explainer=FakeExplainer())
    return TestClient(app)


def _cfg(html: str) -> dict:
    start = html.index('<script id="cfg" type="application/json">') + len(
        '<script id="cfg" type="application/json">'
    )
    return json.loads(html[start : html.index("</script>", start)])


def test_url_lista_para_grabar(client):
    r = client.get("/?dia=viernes&desde=15:52&velocidad=1000&play=1")
    assert r.status_code == 200
    cfg = _cfg(r.text)
    assert cfg["t"] == START + 120  # 15:52 hora del laboratorio (UTC-3)
    assert cfg["speed"] == 1000 and cfg["autoplay"] is True
    assert cfg["utc_offset"] == -3 * 3600
    assert "15:52:00" in r.text


def test_dia_desconocido_da_404(client):
    assert client.get("/?dia=domingo").status_code == 404


def test_estado_en_pausa(client):
    p = client.get(f"/api/estado?dia=viernes&t={START + 100}").json()
    assert p["clock"] == "15:51:40"
    assert p["total"] == 2  # incidente de DoS del modelo y de las reglas
    assert "DoS/DDoS" in p["items"][0]["html"]
    assert p["score"]["model"]["detected"] == 2


def test_sse_reset_ticks_y_fin(client):
    events = []
    with client.stream("GET", f"/stream?dia=viernes&t={START}&velocidad=1000") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("event: "):
                events.append(line.removeprefix("event: "))
    assert events[0] == "reset" and events[-1] == "end"
    assert "tick" in events


def test_explicacion_de_un_incidente(client):
    r = client.get("/alertas/viernes/0")
    assert r.status_code == 200
    assert "Envía paquetes muy deprisa" in r.text
    assert "2 de 2 flujos son ataque" in r.text


def test_falsa_alarma_se_marca_como_tal(client):
    replay_ids = client.get(f"/api/estado?dia=viernes&t={START + 240}").json()["items"]
    scan = next(i for i in replay_ids if "Escaneo" in i["html"])
    r = client.get(f"/alertas/viernes/{scan['id']}")
    assert "Falsa alarma" in r.text


def test_pestana_de_evaluacion(client):
    r = client.get("/evaluacion")
    assert r.status_code == 200
    assert "Ataques conocidos" in r.text and "Ataques nuevos" in r.text


def test_la_pagina_trae_el_estado_inicial_y_puede_abrir_una_alerta(client):
    r = client.get("/?dia=viernes&desde=15:52&alerta=0")
    cfg = _cfg(r.text)
    assert cfg["initial"]["total"] == 2  # ya hay incidentes a las 15:52
    assert 'hx-get="/alertas/friday/0" hx-trigger="load"' in r.text
    assert "Miércoles" in r.text


def test_enlace_directo_a_la_evaluacion_llega_pintado(client):
    r = client.get("/?vista=evaluacion")
    assert "Ataques nuevos" in r.text
    assert "No hay resultados" not in r.text  # los resúmenes de reports/ se leen de verdad


def test_la_evaluacion_incluye_otra_red_si_hay_resultados(client):
    r = client.get("/evaluacion")
    assert "Otra red" in r.text
    # Con reports/other_network/summary.json presente se pinta la tabla, no el aviso.
    assert ("Entrenado en CIC" in r.text) != ("No realizado" in r.text)
