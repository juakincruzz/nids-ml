"""Motor de reproducción del día de test para el panel.

Trabaja con una tabla de flujos ya puntuados (ver nids.replay.build) y responde a tres preguntas:
- ¿Qué incidentes han empezado antes del instante t, y cuántos flujos llevan? (`snapshot`)
- ¿Qué ha pasado entre t0 y t1? (`events_between`), para cada tick del directo.
- ¿Cómo va el marcador en t? (`scoreboard`)

Los tiempos son segundos Unix (UTC) en coma flotante.

Incidentes: el panel no puede listar 250 000 flujos marcados uno a uno. Como haría un SIEM,
las alertas consecutivas con el mismo origen, destino y familia, separadas menos de `gap`
segundos, forman un incidente. Esto agrupa la interfaz; el modelo no ve IPs.
"""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy.special import expit

INCIDENT_GAP_SECONDS = 60
BIN_SECONDS = 10


@dataclass
class Incident:
    id: int
    source: str  # "model" o "rules"
    family: str
    src_ip: str
    dst_ip: str
    times: np.ndarray  # instantes de sus flujos, ordenados
    rep: int  # fila del flujo representativo (el más seguro)
    confidence: float | None
    n_attack: int  # cuántos de sus flujos son ataque según el dataset

    @property
    def start(self) -> float:
        return float(self.times[0])

    @property
    def end(self) -> float:
        return float(self.times[-1])

    def count_until(self, t: float) -> int:
        return int(np.searchsorted(self.times, t, side="right"))


def group_incidents(
    flows: pd.DataFrame, source: str, gap: float = INCIDENT_GAP_SECONDS, first_id: int = 0
) -> list[Incident]:
    """Agrupa las alertas de una fuente (`{source}_flagged`, `{source}_family`)."""
    alerts = flows[flows[f"{source}_flagged"].to_numpy()]
    score_col = f"{source}_score"
    incidents: list[Incident] = []
    keys = alerts[["src_ip", "dst_ip", f"{source}_family"]].astype(str)
    for (src, dst, family), group in alerts.groupby(
        [keys["src_ip"], keys["dst_ip"], keys[f"{source}_family"]], sort=False
    ):
        t = group["t"].to_numpy()
        order = np.argsort(t, kind="stable")
        t, rows = t[order], group.index.to_numpy()[order]
        # Un incidente nuevo cada vez que el hueco entre alertas supera `gap`.
        cuts = np.flatnonzero(np.diff(t) > gap) + 1
        for idx in np.split(np.arange(len(t)), cuts):
            members = rows[idx]
            if score_col in flows:
                scores = flows.loc[members, score_col].to_numpy()
                rep, confidence = members[scores.argmax()], float(expit(scores.max()))
            else:
                rep, confidence = members[0], None
            incidents.append(
                Incident(
                    id=0,
                    source=source,
                    family=family,
                    src_ip=src,
                    dst_ip=dst,
                    times=t[idx],
                    rep=int(rep),
                    confidence=confidence,
                    n_attack=int(flows.loc[members, "is_attack"].sum()),
                )
            )
    incidents.sort(key=lambda inc: (inc.start, inc.source))
    for i, inc in enumerate(incidents, start=first_id):
        inc.id = i
    return incidents


@dataclass
class DayReplay:
    """Un día de test listo para reproducir. `flows` va ordenado por `t`."""

    day: str
    flows: pd.DataFrame
    incidents: list[Incident] = field(default_factory=list)

    def __post_init__(self):
        if not self.incidents:
            model = group_incidents(self.flows, "model")
            rules = group_incidents(self.flows, "rules", first_id=len(model))
            self.incidents = sorted(model + rules, key=lambda inc: (inc.start, inc.id))
            # El id es la posición en la lista ordenada: /alertas/{dia}/{id} lo usa como índice.
            for i, inc in enumerate(self.incidents):
                inc.id = i
        self._starts = np.array([inc.start for inc in self.incidents])
        self._t = self.flows["t"].to_numpy()
        is_attack = self.flows["is_attack"].to_numpy()
        self._cum = {"attack": np.cumsum(is_attack), "benign": np.cumsum(~is_attack)}
        for source in ("model", "rules"):
            flagged = self.flows[f"{source}_flagged"].to_numpy()
            self._cum[f"{source}_tp"] = np.cumsum(flagged & is_attack)
            self._cum[f"{source}_fp"] = np.cumsum(flagged & ~is_attack)

    @property
    def start(self) -> float:
        return float(self._t[0])

    @property
    def end(self) -> float:
        return float(self._t[-1])

    def clamp(self, t: float) -> float:
        return min(max(t, self.start), self.end)

    def snapshot(self, t: float) -> list[tuple[Incident, int]]:
        """Incidentes empezados hasta t (incluido) con los flujos que llevan en t."""
        n = int(np.searchsorted(self._starts, t, side="right"))
        return [(inc, inc.count_until(t)) for inc in self.incidents[:n]]

    def events_between(self, t0: float, t1: float):
        """(incidentes que empiezan en (t0, t1], [(incidente, flujos en t1)] de los abiertos)."""
        lo = int(np.searchsorted(self._starts, t0, side="right"))
        hi = int(np.searchsorted(self._starts, t1, side="right"))
        new = self.incidents[lo:hi]
        updates = [
            (inc, inc.count_until(t1))
            for inc in self.incidents[:lo]
            if inc.end > t0 and inc.count_until(t1) > inc.count_until(t0)
        ]
        return new, updates

    def scoreboard(self, t: float) -> dict:
        """Marcador acumulado desde el inicio de la reproducción hasta t."""
        i = int(np.searchsorted(self._t, t, side="right")) - 1
        hours = (t - self.start) / 3600

        def at(name: str) -> int:
            return int(self._cum[name][i]) if i >= 0 else 0

        attacks = at("attack")
        board = {"flows": i + 1, "attacks": attacks, "hours": hours}
        for source in ("model", "rules"):
            tp, fp = at(f"{source}_tp"), at(f"{source}_fp")
            board[source] = {
                "detected": tp,
                "recall": tp / attacks if attacks else None,
                "false_alarms": fp,
                # Con menos de un minuto la tasa no significa nada.
                "false_alarms_per_hour": fp / hours if hours >= 1 / 60 else None,
            }
        return board

    def timeline(self, bin_seconds: int = BIN_SECONDS) -> dict:
        """Datos estáticos del gráfico: flujos/s, alertas por intervalo y zonas de ataque real."""
        edges = np.arange(self.start, self.end + bin_seconds, bin_seconds)
        b = np.clip(np.searchsorted(edges, self._t, side="right") - 1, 0, len(edges) - 2)
        n_bins = len(edges) - 1

        def per_bin(mask: np.ndarray) -> list[int]:
            return np.bincount(b[mask], minlength=n_bins).tolist()

        everything = np.ones(len(self._t), bool)
        return {
            "start": self.start,
            "end": self.end,
            "bin_seconds": bin_seconds,
            "flows_per_second": [n / bin_seconds for n in per_bin(everything)],
            "model_alerts": per_bin(self.flows["model_flagged"].to_numpy()),
            "rules_alerts": per_bin(self.flows["rules_flagged"].to_numpy()),
            "zones": attack_zones(self.flows, edges, b),
        }


def attack_zones(flows: pd.DataFrame, edges: np.ndarray, b: np.ndarray, max_gap_bins: int = 30):
    """Episodios de ataque real por familia: intervalos con ataques, uniendo huecos de hasta
    `max_gap_bins` intervalos (5 minutos con intervalos de 10 s; un escaneo tiene pausas)."""
    zones = []
    families = flows["family"].astype(str).to_numpy()
    for family in sorted(set(families) - {"benign"}):
        bins = np.unique(b[families == family])
        cuts = np.flatnonzero(np.diff(bins) > max_gap_bins) + 1
        for run in np.split(bins, cuts):
            zones.append(
                {"family": family, "start": float(edges[run[0]]), "end": float(edges[run[-1] + 1])}
            )
    return sorted(zones, key=lambda z: z["start"])
