"""Métricas de detección y elección del umbral.

Todas trabajan con arrays por flujo:
- `is_attack`: verdad (bool), `flagged`: decisión del detector (bool);
- `family`: familia real, `predicted_family`: la que asigna el detector a sus alertas.
"""

import math

import numpy as np
from sklearn.metrics import average_precision_score


def false_alarms_per_hour(is_attack, flagged, hours: float) -> float:
    """Flujos normales marcados como ataque, divididos por la duración real del periodo."""
    false_positives = np.sum(np.asarray(flagged) & ~np.asarray(is_attack))
    return float(false_positives / hours)


def choose_threshold(is_attack, score, hours: float, max_false_alarms_per_hour: float) -> float:
    """Umbral más sensible con falsas alarmas por hora <= presupuesto (se marca si score > t).

    Solo cuentan las puntuaciones de los flujos normales: se permite marcar como mucho
    k = presupuesto · horas de ellos, así que el umbral es la (k+1)-ésima puntuación normal más
    alta. Con empates pueden quedar menos de k, nunca más.
    """
    benign_scores = np.sort(np.asarray(score)[~np.asarray(is_attack)])[::-1]
    allowed = math.floor(max_false_alarms_per_hour * hours)
    if allowed >= len(benign_scores):
        return -math.inf
    return float(benign_scores[allowed])


def detection_metrics(is_attack, flagged, hours: float, score=None) -> dict:
    """Métricas binarias (ataque frente a normal) de un detector en un periodo."""
    is_attack, flagged = np.asarray(is_attack, bool), np.asarray(flagged, bool)
    tp = int(np.sum(flagged & is_attack))
    fp = int(np.sum(flagged & ~is_attack))
    fn = int(np.sum(~flagged & is_attack))
    tn = int(np.sum(~flagged & ~is_attack))
    n = len(is_attack)
    return {
        "precision": tp / (tp + fp) if tp + fp else math.nan,
        "recall": tp / (tp + fn) if tp + fn else math.nan,
        "false_positive_rate": fp / (fp + tn) if fp + tn else math.nan,
        "false_alarms_per_hour": fp / hours,
        "pr_auc": average_precision_score(is_attack, score) if score is not None else math.nan,
        "accuracy": (tp + tn) / n,
        # La de «decir siempre normal»: la accuracy solo se enseña junto a esta.
        "accuracy_always_normal": (fp + tn) / n,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
    }


def metrics_by_family(family, flagged, predicted_family) -> dict[str, dict]:
    """Por familia de ataque: recall de detección y precisión de la familia asignada.

    - recall: de los flujos de la familia, cuántos se marcan como ataque (sea cual sea la
      familia que les ponga el detector). Es lo que importa para no dejar pasar un ataque.
    - precision: de las alertas a las que el detector pone esa familia, cuántas son de verdad
      de ella (incluye como errores las alertas sobre tráfico normal).
    """
    family = np.asarray(family, dtype=object)
    flagged = np.asarray(flagged, bool)
    predicted_family = np.asarray(predicted_family, dtype=object)

    attack_families = sorted(set(family[family != "benign"]) | set(predicted_family[flagged]))
    result = {}
    for fam in attack_families:
        is_fam = family == fam
        alerted_as_fam = flagged & (predicted_family == fam)
        n, n_alerts = int(is_fam.sum()), int(alerted_as_fam.sum())
        result[fam] = {
            "n_flows": n,
            "detected": int((is_fam & flagged).sum()),
            "recall": float((is_fam & flagged).sum() / n) if n else math.nan,
            "n_alerts_as_family": n_alerts,
            "precision": float((alerted_as_fam & is_fam).sum() / n_alerts)
            if n_alerts
            else math.nan,
        }
    return result
