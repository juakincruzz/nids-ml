"""`make explain`: ejemplos de alertas explicadas e importancia global de las variables.

Recorre los días de test de uno en uno (para no cargar todo a la vez) y guarda en
reports/explanations/:
- examples.json: la primera alerta acertada de cada familia y las primeras falsas alarmas;
- global_importance.csv y .png: contribución media de cada variable en una muestra de alertas.
"""

import gc

import joblib
import numpy as np
import pandas as pd

from nids.config import load_config, project_path
from nids.data.load import load_processed
from nids.evaluation.plots import plot_global_importance
from nids.evaluation.report import write_json
from nids.evaluation.split import TEST, temporal_split
from nids.explain.explainer import AlertExplainer
from nids.explain.phrases import FEATURES
from nids.models.rules import rule_scores

ALERTS_PER_DAY_FOR_IMPORTANCE = 400
FALSE_ALARM_EXAMPLES = 2


def main() -> None:
    config = load_config()
    split, rules_cfg = config["split"], config["rules"]
    clf = joblib.load(project_path(config, "models") / "lightgbm.joblib")
    explainer = AlertExplainer(clf, rules_cfg["thresholds"], rules_cfg["window_seconds"])
    rng = np.random.default_rng(config["seed"])

    examples, false_alarms, importance = {}, [], []
    for day in config["dataset"]["cicids2017"]["days"]:
        print(f"Explicando alertas de test del {day}…", flush=True)
        df = load_processed(config, [day])
        test = df[temporal_split(df, split["train_fraction"], split["validation_fraction"]) == TEST]
        del df
        _, flagged, _ = clf.predict(test)
        stats = rule_scores(
            test,
            rules_cfg["window_seconds"],
            rules_cfg["brute_force_ports"],
            rules_cfg["brute_force_max_duration_seconds"],
        )

        alerts = np.flatnonzero(flagged)
        is_attack = test["is_attack"].to_numpy()
        family = test["family"].astype(str).to_numpy()
        picks = []  # (posición, tipo)
        for fam in sorted(set(family[alerts][is_attack[alerts]])):
            if fam not in examples:
                picks.append((alerts[(family[alerts] == fam)][0], fam))
        for pos in alerts[~is_attack[alerts]][: FALSE_ALARM_EXAMPLES - len(false_alarms)]:
            picks.append((pos, "false_alarm"))

        if picks:
            positions = [p for p, _ in picks]
            explained = explainer.explain(test.iloc[positions], stats.iloc[positions])
            for (pos, kind), exp in zip(picks, explained, strict=True):
                row = test.iloc[pos]
                exp |= {
                    "timestamp_utc": row["timestamp"].isoformat(),
                    "day": day,
                    "true_label": str(row["label"]),
                    "dst_port": int(row["Dst Port"]),
                }
                if kind == "false_alarm":
                    false_alarms.append(exp)
                else:
                    examples[kind] = exp

        if len(alerts):
            sample = rng.choice(alerts, min(ALERTS_PER_DAY_FOR_IMPORTANCE, len(alerts)), False)
            X = clf.cleaner_.transform(test.iloc[sample])
            z = clf.logits(test.iloc[sample])
            attack_cols = [i for i in range(len(clf.classes_)) if i != explainer.benign]
            best = np.array(attack_cols)[z[:, attack_cols].argmax(axis=1)]
            importance.append(pd.DataFrame(explainer.contributions(X, best), columns=X.columns))
        del test, stats
        gc.collect()

    out_dir = project_path(config, "reports") / "explanations"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "examples.json", {"by_family": examples, "false_alarms": false_alarms})

    contrib = pd.concat(importance)
    table = (
        pd.DataFrame(
            {
                "mean_abs_contribution": contrib.abs().mean(),
                "mean_contribution": contrib.mean(),
                "name": [FEATURES[f][0] for f in contrib.columns],
            }
        )
        .sort_values("mean_abs_contribution", ascending=False)
        .rename_axis("feature")
    )
    table.to_csv(out_dir / "global_importance.csv")
    plot_global_importance(
        table.head(15),
        out_dir / "global_importance.png",
        f"Qué pesa más en las alertas (SHAP, {len(contrib):_} alertas de test)".replace("_", " "),
    )
    _print(examples, false_alarms)


def _percent(x: float) -> str:
    return f"{x:.1%}".replace(".", ",").replace("%", " %")


def _print(examples: dict, false_alarms: list) -> None:
    for title, exp in [*examples.items(), *(("falsa alarma", e) for e in false_alarms)]:
        print(
            f"\n[{title}] {exp['true_label']} · {exp['timestamp_utc']} · puerto {exp['dst_port']}"
        )
        print(f"  El modelo dice: {exp['family']} (confianza {_percent(exp['confidence'])})")
        for r in exp["reasons"]:
            print(f"  - {r['text']}: {r['value']} (lo normal: {r['normal']})")
        rules = exp["rules"]
        print(f"  Reglas clásicas: {'la habrían detectado' if rules['would_detect'] else 'no'}")


if __name__ == "__main__":
    main()
