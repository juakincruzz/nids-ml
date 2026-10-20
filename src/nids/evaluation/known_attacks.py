"""Protocolo «ataques conocidos»: reparto temporal dentro de cada día, evaluación en test.

Salidas en reports/known_attacks/: metrics.csv, summary.json y dos gráficos. Las predicciones
completas del test van a data/predictions/ (no se versionan); el panel las usará.
"""

import joblib
import numpy as np
import pandas as pd

from nids.config import project_path
from nids.data.labels import ATTACK_FAMILIES
from nids.data.load import load_processed
from nids.evaluation.metrics import detection_metrics, metrics_by_family
from nids.evaluation.plots import plot_pr_curves, plot_recall_by_family
from nids.evaluation.report import write_json
from nids.evaluation.split import TEST, TRAIN, VALIDATION, part_hours, temporal_split
from nids.models.rules import apply_rules, rule_scores

CLASSIFIERS = ("lightgbm", "logistic_regression")


def run(config: dict) -> dict:
    split, rules_cfg = config["split"], config["rules"]
    thresholds = rules_cfg["thresholds"]
    if any(v is None for v in thresholds.values()):
        raise ValueError("Faltan los umbrales de las reglas en el config: ejecuta `make train`.")

    df = load_processed(config)
    part = temporal_split(df, split["train_fraction"], split["validation_fraction"])
    hours = part_hours(df, split["train_fraction"], split["validation_fraction"])
    test = df[part == TEST]
    is_attack = test["is_attack"].to_numpy()

    detectors = {}
    for name in CLASSIFIERS:
        clf = joblib.load(project_path(config, "models") / f"{name}.joblib")
        score, flagged, family = clf.predict(test)
        detectors[name] = {
            "score": score,
            "flagged": flagged,
            "family": family,
            "threshold": clf.threshold_,
        }

    scores = rule_scores(
        test,
        rules_cfg["window_seconds"],
        rules_cfg["brute_force_ports"],
        rules_cfg["brute_force_max_duration_seconds"],
    )
    flagged, family = apply_rules(scores, thresholds)
    detectors["rules"] = {
        "score": None,
        "flagged": flagged,
        "family": family,
        "threshold": thresholds,
    }
    detectors["always_normal"] = {
        "score": np.zeros(len(test)),
        "flagged": np.zeros(len(test), bool),
        "family": np.full(len(test), "benign", dtype=object),
        "threshold": None,
    }

    for det in detectors.values():
        det["metrics"] = detection_metrics(is_attack, det["flagged"], hours[TEST], det["score"])
        det["by_family"] = metrics_by_family(test["family"], det["flagged"], det["family"])

    out_dir = project_path(config, "reports") / "known_attacks"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = _summary(config, df, part, hours, detectors)
    write_json(out_dir / "summary.json", summary)
    _metrics_table(detectors).to_csv(out_dir / "metrics.csv", index=False)
    title = f"Ataques conocidos: test ({hours[TEST]:.1f} h, 30 % final de cada día)"
    plot_pr_curves(is_attack, detectors, out_dir / "pr_curves.png", title)
    plot_recall_by_family(
        {n: d["by_family"] for n, d in detectors.items()},
        out_dir / "recall_by_family.png",
        "Recall por familia en test",
    )
    _save_predictions(config, test, detectors, scores)
    return summary


def _summary(config, df, part, hours, detectors) -> dict:
    # crosstab en vez de df.assign(...): no copia el DataFrame entero.
    counts = pd.crosstab(df["family"].astype(str), part).reindex(
        columns=[TRAIN, VALIDATION, TEST], fill_value=0
    )
    seen_before_test = counts[TRAIN] + counts[VALIDATION]
    return {
        "protocol": "known_attacks",
        "split": config["split"],
        "max_false_alarms_per_hour": config["evaluation"]["max_false_alarms_per_hour"],
        "hours": hours,
        "flows_per_family": counts.to_dict(orient="index"),
        "families_without_test_flows": [
            f for f in ATTACK_FAMILIES if f in counts.index and counts.loc[f, TEST] == 0
        ],
        "families_only_in_test": [
            f
            for f in ATTACK_FAMILIES
            if f in counts.index and counts.loc[f, TEST] > 0 and seen_before_test[f] == 0
        ],
        "detectors": {
            name: {
                "threshold": d["threshold"],
                "metrics": d["metrics"],
                "by_family": d["by_family"],
            }
            for name, d in detectors.items()
        },
    }


def _metrics_table(detectors) -> pd.DataFrame:
    rows = []
    for name, d in detectors.items():
        rows.append({"detector": name, "scope": "all"} | d["metrics"])
        for fam, m in d["by_family"].items():
            rows.append({"detector": name, "scope": fam} | m)
    return pd.DataFrame(rows)


def _save_predictions(config, test, detectors, rule_stats) -> None:
    out = project_path(config, "processed_data").parent / "predictions"
    out.mkdir(parents=True, exist_ok=True)
    pred = test[
        ["timestamp", "day", "src_ip", "dst_ip", "Dst Port", "label", "family", "is_attack"]
    ].copy()
    for name in (*CLASSIFIERS, "rules"):
        d = detectors[name]
        if d["score"] is not None:
            pred[f"{name}_score"] = d["score"]
        pred[f"{name}_flagged"] = d["flagged"]
        pred[f"{name}_family"] = d["family"]
    for rule in rule_stats:
        pred[f"rule_{rule}_stat"] = rule_stats[rule].to_numpy()
    pred.to_parquet(out / "known_attacks_test.parquet", index=False)
