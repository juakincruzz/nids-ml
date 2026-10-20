"""Protocolo «ataques nuevos»: ¿se detecta una familia que nunca se ha visto al entrenar?

Para cada familia F (leave-one-attack-family-out):
- LightGBM binario (ataque/normal) entrenado con todo lo anterior al corte de test salvo F;
  umbral con el tráfico normal de validación, como en «ataques conocidos».
- Recall: sobre TODOS los flujos de F, de cualquier momento (el modelo no ha visto ninguno).
- Falsas alarmas por hora: sobre el tráfico normal de test.

Referencias, que no dependen de F porque nunca ven ataques al ajustarse:
- Isolation Forest entrenado solo con tráfico normal (se ajusta una vez).
- Reglas de umbral (sus umbrales solo dependen del tráfico normal).

Heartbleed (11 flujos) no tiene ejecución propia: no se ve nunca en train, en ningún protocolo.
Los modelos de este protocolo no se guardan: solo sirven para medir.
"""

import gc
import math

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from nids.config import project_path
from nids.data.load import load_processed
from nids.evaluation.plots import plot_recall_by_family
from nids.evaluation.report import write_json
from nids.evaluation.split import (
    TEST,
    TRAIN,
    VALIDATION,
    fit_and_threshold_sets,
    part_hours,
    temporal_split,
)
from nids.models.anomaly import AnomalyDetector
from nids.models.classifiers import FlowClassifier, make_lightgbm
from nids.models.rules import apply_rules, rule_scores

LOFO_FAMILIES = ("dos", "brute_force", "scan", "web", "botnet", "infiltration")


def family_result(fam, family, is_benign, flagged, hours: float, score=None) -> dict:
    """Recall sobre la familia y falsas alarmas sobre el tráfico normal del conjunto evaluado.

    La PR-AUC compara la familia solo contra el tráfico normal; como depende de la proporción de
    la familia, se guarda esa proporción al lado (es la PR-AUC de puntuar al azar).
    """
    is_fam = np.asarray(family) == fam
    flagged, is_benign = np.asarray(flagged, bool), np.asarray(is_benign, bool)
    n = int(is_fam.sum())
    keep = is_fam | is_benign
    result = {
        "n_flows": n,
        "detected": int((flagged & is_fam).sum()),
        "recall": float((flagged & is_fam).sum() / n) if n else math.nan,
        "false_alarms_per_hour": float((flagged & is_benign).sum() / hours),
        "prevalence": float(is_fam[keep].mean()),
        "pr_auc": math.nan,
    }
    if score is not None and n:
        result["pr_auc"] = float(average_precision_score(is_fam[keep], np.asarray(score)[keep]))
    return result


def run(config: dict) -> dict:
    split, rules_cfg = config["split"], config["rules"]
    seed, n_jobs = config["seed"], config["n_jobs"]
    budget = config["evaluation"]["max_false_alarms_per_hour"]

    df = load_processed(config)
    part = temporal_split(df, split["train_fraction"], split["validation_fraction"])
    hours = part_hours(df, split["train_fraction"], split["validation_fraction"])
    is_attack = df["is_attack"].to_numpy()

    # Conjunto evaluado: todos los ataques (de cualquier momento) + el tráfico normal de test.
    evaluated = is_attack | (part == TEST).to_numpy()
    ev = df[evaluated]
    ev_family = ev["family"].astype(str).to_numpy()
    ev_benign = ~ev["is_attack"].to_numpy()

    results: dict[str, dict] = {"lightgbm_lofo": {}, "isolation_forest": {}, "rules": {}}

    for fam in LOFO_FAMILIES:
        print(f"LightGBM sin «{fam}»…", flush=True)
        fit, threshold = fit_and_threshold_sets(df, part, exclude_family=fam)
        clf = FlowClassifier(
            f"lightgbm_without_{fam}", make_lightgbm(config["model"], seed, n_jobs), binary=True
        ).fit(fit, threshold, hours[VALIDATION], budget)
        del fit, threshold
        gc.collect()
        score, flagged, _ = clf.predict(ev)
        results["lightgbm_lofo"][fam] = family_result(
            fam, ev_family, ev_benign, flagged, hours[TEST], score
        ) | {"threshold": clf.threshold_}
        del clf, score, flagged
        gc.collect()

    print("Isolation Forest (solo tráfico normal)…", flush=True)
    detector = AnomalyDetector(
        config["anomaly"]["n_estimators"], config["anomaly"]["max_samples"], seed, n_jobs
    ).fit(
        df[(part == TRAIN).to_numpy() & ~is_attack],
        df[(part == VALIDATION).to_numpy() & ~is_attack],
        hours[VALIDATION],
        budget,
    )
    score, flagged = detector.predict(ev)
    for fam in LOFO_FAMILIES:
        results["isolation_forest"][fam] = family_result(
            fam, ev_family, ev_benign, flagged, hours[TEST], score
        ) | {"threshold": detector.threshold_}
    del detector, score
    gc.collect()

    print("Reglas…", flush=True)
    stats = rule_scores(
        df,
        rules_cfg["window_seconds"],
        rules_cfg["brute_force_ports"],
        rules_cfg["brute_force_max_duration_seconds"],
        group_by=part,
    )
    flagged, _ = apply_rules(stats, rules_cfg["thresholds"])
    for fam in LOFO_FAMILIES:
        results["rules"][fam] = family_result(
            fam, ev_family, ev_benign, flagged[evaluated], hours[TEST]
        )

    out_dir = project_path(config, "reports") / "novel_attacks"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "protocol": "novel_attacks",
        "max_false_alarms_per_hour": budget,
        "test_hours": hours[TEST],
        "notes": [
            "Recall sobre todos los flujos de la familia excluida, de cualquier momento.",
            "Falsas alarmas por hora sobre el tráfico normal del periodo de test.",
            "Isolation Forest y reglas no ven ataques al ajustarse: no dependen de la familia.",
            "Heartbleed (11 flujos) no tiene ejecución propia: nunca se ve en train.",
        ],
        "detectors": results,
    }
    write_json(out_dir / "summary.json", summary)
    pd.DataFrame(
        [
            {"detector": det, "family": fam} | metrics
            for det, by_family in results.items()
            for fam, metrics in by_family.items()
        ]
    ).to_csv(out_dir / "metrics.csv", index=False)
    plot_recall_by_family(
        results,
        out_dir / "recall_by_family.png",
        "Ataques nuevos: recall de cada familia sin haberla visto al entrenar",
    )
    return summary
