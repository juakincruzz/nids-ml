"""Precálculo de la reproducción: puntúa la parte de test de cada día con el modelo y las reglas.

Deja en data/replay/{día}.parquet una fila por flujo con lo que necesita el panel: hora, IPs,
etiqueta real, decisión del modelo, decisión de las reglas, sus estadísticos y las variables
(para explicar con SHAP la alerta que se pulse). Así el panel arranca en segundos.
"""

from pathlib import Path

import pandas as pd

from nids.config import project_path
from nids.data.load import load_processed
from nids.evaluation.split import TEST, temporal_split
from nids.models.classifiers import FlowClassifier
from nids.models.rules import RULES, apply_rules, rule_scores


def replay_dir(config: dict) -> Path:
    return project_path(config, "processed_data").parent / "replay"


def build_day(config: dict, day: str, clf: FlowClassifier) -> pd.DataFrame:
    split, rules_cfg = config["split"], config["rules"]
    df = load_processed(config, [day])
    test = df[temporal_split(df, split["train_fraction"], split["validation_fraction"]) == TEST]
    test = test.reset_index(drop=True)
    del df

    score, flagged, family = clf.predict(test)
    stats = rule_scores(
        test,
        rules_cfg["window_seconds"],
        rules_cfg["brute_force_ports"],
        rules_cfg["brute_force_max_duration_seconds"],
    )
    rules_flagged, rules_family = apply_rules(stats, rules_cfg["thresholds"])

    out = test[["timestamp", "src_ip", "dst_ip", "label", "family", "is_attack"]].copy()
    # Segundos Unix. Restando la época no depende de la resolución interna (ns o µs) del datetime.
    out["t"] = (test["timestamp"] - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    for col in ("src_ip", "dst_ip", "label", "family"):
        out[col] = out[col].astype(str)
    out["model_score"] = score
    out["model_flagged"] = flagged
    out["model_family"] = family.astype(str)
    out["rules_flagged"] = rules_flagged
    out["rules_family"] = rules_family.astype(str)
    for rule in RULES:
        out[f"rule_{rule}"] = stats[rule].to_numpy()
    features = test[clf.cleaner_.features_]
    return pd.concat([out, features], axis=1)


def load_day(config: dict, day: str) -> pd.DataFrame:
    path = replay_dir(config) / f"{day}.parquet"
    if not path.exists():
        raise FileNotFoundError(
            f"No hay reproducción precalculada de {day}: ejecuta `make replay`."
        )
    return pd.read_parquet(path)
