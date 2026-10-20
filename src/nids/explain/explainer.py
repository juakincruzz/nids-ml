"""Explicación de cada alerta del modelo principal (LightGBM multiclase) con SHAP.

Se explica por qué el flujo parece de la familia que le asigna el modelo y no normal:

    logit[familia] − logit[normal] = base + Σ_variables (φ_familia − φ_normal)

TreeExplainer da los φ de cada clase de forma exacta (la suma cuadra con los logits), así que la
contribución de cada variable a esa diferencia es φ_familia − φ_normal. Se enseñan las 3 que más
empujan hacia la alerta, con su valor y lo que sería normal.

Además se dice si las reglas clásicas la habrían detectado, con su estadístico y su umbral.
"""

import numpy as np
import pandas as pd
import shap
from scipy.special import expit

from nids.explain.phrases import FEATURES, describe, format_value
from nids.models.classifiers import FlowClassifier
from nids.models.rules import RULES

# regla -> (nombre, qué mide, unidad para format_value)
RULE_NAMES = {
    "scan": ("escaneo", "puertos de destino distintos en {w} s", "count"),
    "brute_force": ("fuerza bruta", "conexiones cortas a FTP/SSH en {w} s", "count"),
    "dos": ("DoS", "hacia el mismo destino durante {w} s", "pkt/s"),
}


class AlertExplainer:
    def __init__(
        self,
        clf: FlowClassifier,
        rule_thresholds: dict[str, float],
        window_seconds: int = 60,
        top_k: int = 3,
    ):
        if clf.binary:
            raise ValueError("El explicador espera el modelo multiclase (asigna familia).")
        self.clf = clf
        self.rule_thresholds = rule_thresholds
        self.window_seconds = window_seconds
        self.top_k = top_k
        self.tree = shap.TreeExplainer(clf.estimator)
        self.benign = clf.classes_.index("benign")

    def contributions(self, X: pd.DataFrame, family_index: np.ndarray) -> np.ndarray:
        """Contribución de cada variable a logit[familia] − logit[normal], fila a fila."""
        phi = self.tree.shap_values(X)  # (flujos, variables, clases)
        rows = np.arange(len(X))
        return phi[rows, :, family_index] - phi[:, :, self.benign]

    def explain(self, flows: pd.DataFrame, rule_stats: pd.DataFrame | None = None) -> list[dict]:
        """Explica cada flujo de `flows` (normalmente, las alertas)."""
        X = self.clf.cleaner_.transform(flows)
        score, flagged, family = self.clf.predict(flows)
        # Si un flujo no es alerta, se explica la familia de ataque más probable.
        z = self.clf.logits(flows)
        attack_cols = [i for i in range(len(self.clf.classes_)) if i != self.benign]
        best = np.array(attack_cols)[z[:, attack_cols].argmax(axis=1)]
        contrib = self.contributions(X, best)

        features = list(X.columns)
        normal = self.clf.benign_medians_
        explanations = []
        for i in range(len(flows)):
            order = np.argsort(contrib[i])[::-1][: self.top_k]
            reasons = []
            for j in order:
                feature, value = features[j], float(X.iloc[i, j])
                unit = FEATURES[feature][1]
                reasons.append(
                    {
                        "feature": feature,
                        "text": describe(feature, value, float(normal[feature])),
                        "value": format_value(value, unit),
                        "normal": format_value(float(normal[feature]), unit),
                        "contribution": float(contrib[i, j]),
                    }
                )
            explanation = {
                "family": self.clf.classes_[best[i]],
                "is_alert": bool(flagged[i]),
                "confidence": float(expit(score[i])),
                "reasons": reasons,
            }
            if rule_stats is not None:
                explanation["rules"] = self._rules(rule_stats.iloc[i])
            explanations.append(explanation)
        return explanations

    def _rules(self, stats: pd.Series) -> dict:
        """¿La habrían detectado las reglas? Con el estadístico de cada una y su umbral."""
        detail = []
        for rule in RULES:
            name, what, unit = RULE_NAMES[rule]
            value, threshold = float(stats[rule]), float(self.rule_thresholds[rule])
            what = what.format(w=self.window_seconds)
            detail.append(
                {
                    "rule": rule,
                    "fired": value > threshold,
                    "text": f"{name}: {format_value(value, unit)} {what} "
                    f"(salta con más de {format_value(threshold, unit)})",
                }
            )
        return {"would_detect": any(d["fired"] for d in detail), "detail": detail}
