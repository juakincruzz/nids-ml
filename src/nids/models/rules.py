"""Referencia: reglas de umbral al estilo de un IDS clásico.

Cada regla calcula un estadístico por grupo (IP de origen y ventana fija de tiempo) y se lo
asigna a todos los flujos del grupo. La regla salta si el estadístico supera su umbral.

- scan: número de puertos de destino distintos que toca la IP de origen en la ventana.
- brute_force: número de conexiones cortas a los puertos de login (21/22) en la ventana; solo
  se asigna a esas conexiones.
- dos: paquetes por segundo de una IP de origen hacia una misma IP de destino en la ventana.

Las reglas sí usan IPs para agrupar, como haría un IDS real. El modelo no.
"""

import numpy as np
import pandas as pd

from nids.evaluation.metrics import choose_threshold

RULES = ("scan", "brute_force", "dos")
# Si saltan varias, la alerta se atribuye a la primera de esta lista.
_PRIORITY = ("brute_force", "scan", "dos")


def rule_scores(
    df: pd.DataFrame,
    window_seconds: int,
    brute_force_ports: list[int],
    brute_force_max_duration_seconds: float,
    group_by: pd.Series | None = None,
) -> pd.DataFrame:
    """Estadístico de cada regla para cada flujo.

    `group_by` (p. ej., la parte del reparto) evita que una ventana mezcle flujos de train y de
    test en el borde del corte.
    """
    window = df["timestamp"].dt.floor(f"{window_seconds}s")
    extra = [group_by.to_numpy()] if group_by is not None else []
    src_window = [*extra, df["src_ip"].to_numpy(), window.to_numpy()]

    scan = df.groupby(src_window, observed=True)["Dst Port"].transform("nunique")

    # Flow Duration viene en microsegundos (CICFlowMeter).
    login = df["Dst Port"].isin(brute_force_ports) & (
        df["Flow Duration"] <= brute_force_max_duration_seconds * 1e6
    )
    login_count = login.groupby(src_window, observed=True).transform("sum")
    brute_force = login_count.where(login, 0)

    packets = df["Total Fwd Packet"] + df["Total Bwd packets"]
    src_dst_window = [*src_window, df["dst_ip"].to_numpy()]
    dos = packets.groupby(src_dst_window, observed=True).transform("sum") / window_seconds

    return pd.DataFrame(
        {"scan": scan, "brute_force": brute_force, "dos": dos}, index=df.index
    ).astype("float64")


def tune_thresholds(
    scores: pd.DataFrame, is_attack, hours: float, max_false_alarms_per_hour: float
) -> dict[str, float]:
    """Umbral de cada regla con un tercio del presupuesto de falsas alarmas por hora."""
    budget = max_false_alarms_per_hour / len(RULES)
    return {
        rule: choose_threshold(is_attack, scores[rule].to_numpy(), hours, budget) for rule in RULES
    }


def apply_rules(
    scores: pd.DataFrame, thresholds: dict[str, float]
) -> tuple[np.ndarray, np.ndarray]:
    """Devuelve (marcado, familia atribuida) para cada flujo. Sin alerta, la familia es 'benign'."""
    fired = {rule: scores[rule].to_numpy() > thresholds[rule] for rule in RULES}
    flagged = np.logical_or.reduce(list(fired.values()))
    family = np.full(len(scores), "benign", dtype=object)
    for rule in reversed(_PRIORITY):  # la de más prioridad se escribe la última
        family[fired[rule]] = rule
    return flagged, family
