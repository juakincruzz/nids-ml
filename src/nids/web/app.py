"""Panel web: reproducción del día de test con alertas en directo (FastAPI + Jinja2 + HTMX + SSE).

Rutas:
- GET /                      panel. Parámetros: dia, desde (HH:MM, hora local), velocidad, play.
                             Ej.: /?dia=viernes&desde=15:50&velocidad=300&play=1
- GET /stream                SSE: un evento «reset» con el estado en t y luego un «tick» cada
                             250 ms con la hora simulada, el marcador y los incidentes nuevos
                             (ya en HTML). Pausar, cambiar de velocidad o saltar = reconectar.
- GET /api/estado            el mismo «reset», para cuando se salta estando en pausa.
- GET /alertas/{dia}/{id}    explicación de un incidente (fragmento HTML para HTMX).
- GET /evaluacion            tablas de los protocolos (fragmento HTML para HTMX).

El reloj de la reproducción lo lleva el servidor; el navegador solo pinta.
"""

import asyncio
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from nids.config import project_path
from nids.explain.explainer import AlertExplainer
from nids.models.rules import RULES
from nids.replay.build import load_day
from nids.replay.engine import DayReplay, Incident

HERE = Path(__file__).parent
TICK_SECONDS = 0.25
SPEEDS = (60, 300, 1000)
MAX_LISTED = 60  # incidentes que se pintan a la vez en la lista

DAYS = {
    "lunes": "monday",
    "martes": "tuesday",
    "miercoles": "wednesday",
    "jueves": "thursday",
    "viernes": "friday",
}
DAY_NAMES = {english: spanish for spanish, english in DAYS.items()} | {"wednesday": "miércoles"}
FAMILY_NAMES = {
    "benign": "Normal",
    "dos": "DoS/DDoS",
    "brute_force": "Fuerza bruta",
    "scan": "Escaneo",
    "web": "Ataque web",
    "botnet": "Botnet",
    "infiltration": "Infiltración",
    "heartbleed": "Heartbleed",
}
SOURCE_NAMES = {"model": "Modelo", "rules": "Reglas"}


def _number(x, decimals: int = 0) -> str:
    """12345.6 -> «12 345,6» (formato español)."""
    if x is None:
        return "—"
    return f"{x:,.{decimals}f}".replace(",", " ").replace(".", ",")


def _percent(x, decimals: int = 1) -> str:
    return "—" if x is None else f"{_number(100 * x, decimals)} %"


def create_app(
    config: dict,
    replays: Callable[[str], DayReplay] | None = None,
    explainer: AlertExplainer | None = None,
) -> FastAPI:
    """Crea la aplicación. Los tests inyectan `replays` y `explainer` con datos sintéticos."""
    tz = ZoneInfo(config["dataset"]["cicids2017"]["display_timezone"])
    reports_dir = project_path(config, "reports")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters |= {
        "number": _number,
        "percent": _percent,
        "family": lambda f: FAMILY_NAMES.get(f, f),
        "source": lambda s: SOURCE_NAMES.get(s, s),
        # Mayúscula solo en la primera letra («ventana TCP», no «ventana tcp» como capitalize).
        "sentence": lambda s: s[:1].upper() + s[1:],
    }

    if replays is None:

        @lru_cache(maxsize=2)
        def replays(day: str) -> DayReplay:
            return DayReplay(day, load_day(config, day))

    state = {"explainer": explainer}

    def get_explainer() -> AlertExplainer:
        if state["explainer"] is None:
            clf = joblib.load(project_path(config, "models") / "lightgbm.joblib")
            rules = config["rules"]
            state["explainer"] = AlertExplainer(clf, rules["thresholds"], rules["window_seconds"])
        return state["explainer"]

    def resolve_day(dia: str) -> str:
        day = DAYS.get(dia.lower().replace("é", "e"), dia.lower())
        if day not in DAY_NAMES:
            raise HTTPException(404, f"Día desconocido: {dia}")
        return day

    def clock(t: float) -> str:
        return datetime.fromtimestamp(t, UTC).astimezone(tz).strftime("%H:%M:%S")

    def parse_desde(replay: DayReplay, desde: str | None) -> float:
        """«15:50» (hora local del laboratorio) -> segundos Unix dentro de la ventana de test."""
        if not desde:
            return replay.start
        try:
            hour, minute = (int(x) for x in desde.split(":"))
        except ValueError as error:
            raise HTTPException(400, "desde tiene que ser HH:MM") from error
        local_day = datetime.fromtimestamp(replay.start, UTC).astimezone(tz)
        local = local_day.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return replay.clamp(local.timestamp())

    def alert_item(day: str, inc: Incident, n: int) -> dict:
        html = templates.get_template("_alert.html").render(
            day=day, inc=inc, n=n, time=clock(inc.start)
        )
        return {"id": inc.id, "html": html}

    def reset_payload(day: str, replay: DayReplay, t: float) -> dict:
        snapshot = replay.snapshot(t)
        return {
            "t": t,
            "clock": clock(t),
            "score": replay.scoreboard(t),
            "total": len(snapshot),
            "items": [alert_item(day, inc, n) for inc, n in snapshot[-MAX_LISTED:]],
        }

    app = FastAPI(title="NIDS-ML")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        dia: str = "viernes",
        desde: str | None = None,
        velocidad: int = 300,
        play: int = 0,
        vista: str = "directo",
        alerta: int | None = None,
    ):
        day = resolve_day(dia)
        replay = replays(day)
        t0 = parse_desde(replay, desde)
        offset = datetime.fromtimestamp(replay.start, UTC).astimezone(tz).utcoffset()
        cfg = {
            "day": day,
            "t": t0,
            "speed": velocidad if velocidad in SPEEDS else 300,
            "speeds": SPEEDS,
            "autoplay": bool(play),
            "utc_offset": offset.total_seconds() if offset else 0,
            "timeline": replay.timeline(),
            "families": FAMILY_NAMES,
            # Estado inicial incrustado: la página sale completa sin esperar a otra petición.
            "initial": reset_payload(day, replay, t0),
        }
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "cfg_json": json.dumps(cfg),
                "day": day,
                "day_name": DAY_NAMES[day],
                "days": [(es, DAY_NAMES[en], en) for es, en in DAYS.items()],
                "start": clock(replay.start),
                "end": clock(replay.end),
                "now": clock(t0),
                "utc_label": _utc_label(offset),
                "speed": cfg["speed"],
                "speeds": SPEEDS,
                "vista": vista,
                "alerta": alerta
                if alerta is not None and 0 <= alerta < len(replay.incidents)
                else None,
                # Con ?vista=evaluacion la pestaña llega ya pintada (enlace directo, sin esperas).
                **(_evaluation_context(reports_dir) if vista == "evaluacion" else {}),
            },
        )

    @app.get("/api/estado")
    def estado(dia: str, t: float):
        day = resolve_day(dia)
        replay = replays(day)
        return JSONResponse(reset_payload(day, replay, replay.clamp(t)))

    @app.get("/stream")
    async def stream(request: Request, dia: str, t: float, velocidad: int = 300):
        day = resolve_day(dia)
        replay = replays(day)
        speed = velocidad if velocidad in SPEEDS else 300

        async def events():
            now = replay.clamp(t)
            yield _sse("reset", reset_payload(day, replay, now))
            last = time.monotonic()
            while now < replay.end:
                await asyncio.sleep(TICK_SECONDS)
                if await request.is_disconnected():
                    return
                real = time.monotonic()
                later = min(replay.end, now + (real - last) * speed)
                last = real
                new, updates = replay.events_between(now, later)
                now = later
                yield _sse(
                    "tick",
                    {
                        "t": now,
                        "clock": clock(now),
                        "score": replay.scoreboard(now),
                        "new": [alert_item(day, inc, inc.count_until(now)) for inc in new],
                        "updates": [{"id": inc.id, "n": n} for inc, n in updates],
                    },
                )
            yield _sse("end", {"t": now})

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/alertas/{dia}/{incident_id}", response_class=HTMLResponse)
    def alerta(request: Request, dia: str, incident_id: int):
        day = resolve_day(dia)
        replay = replays(day)
        if not 0 <= incident_id < len(replay.incidents):
            raise HTTPException(404, "Incidente desconocido")
        inc = replay.incidents[incident_id]
        row = replay.flows.iloc[[inc.rep]]
        stats = row[[f"rule_{r}" for r in RULES]].set_axis(list(RULES), axis=1)
        [explanation] = get_explainer().explain(row, stats)
        n_flows = len(inc.times)
        return templates.TemplateResponse(
            request,
            "_detail.html",
            {
                "inc": inc,
                "exp": explanation,
                "start": clock(inc.start),
                "end": clock(inc.end),
                "n_flows": n_flows,
                "dst_port": int(row["Dst Port"].iloc[0]),
                "true_label": str(row["label"].iloc[0]),
                "is_false_alarm": inc.n_attack == 0,
            },
        )

    @app.get("/evaluacion", response_class=HTMLResponse)
    def evaluacion(request: Request):
        return templates.TemplateResponse(
            request, "_evaluation.html", _evaluation_context(reports_dir)
        )

    return app


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _utc_label(offset: timedelta | None) -> str:
    hours = int(offset.total_seconds() // 3600) if offset else 0
    return f"UTC{hours:+d}" if hours else "UTC"


def _evaluation_context(reports_dir: Path) -> dict:
    """Lee los resúmenes de reports/ (si un protocolo no se ha ejecutado, se dice)."""

    def read(name: str) -> dict | None:
        path = reports_dir / name / "summary.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    return {
        "known": read("known_attacks"),
        "novel": read("novel_attacks"),
        "other": read("other_network"),
    }
