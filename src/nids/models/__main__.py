"""`make train`: umbrales de las reglas y clasificadores (protocolo «ataques conocidos»).

- Reglas: umbrales con todo lo anterior al corte de test (train + validación).
- Clasificadores: se ajustan con train (+ los ataques del tramo de validación) y eligen su
  umbral con el tráfico normal de validación.
Nada de esta fase ve test.
"""

import gc
import math

import joblib

from nids.config import load_config, project_path, set_seeds
from nids.data.load import load_processed
from nids.evaluation.split import (
    TEST,
    TRAIN,
    VALIDATION,
    fit_and_threshold_sets,
    part_hours,
    temporal_split,
)
from nids.models.classifiers import FlowClassifier, make_lightgbm, make_logistic
from nids.models.rules import rule_scores, tune_thresholds


def main() -> None:
    config = load_config()
    seed = config["seed"]
    set_seeds(seed)
    split, rules_cfg = config["split"], config["rules"]
    budget = config["evaluation"]["max_false_alarms_per_hour"]

    df = load_processed(config)
    part = temporal_split(df, split["train_fraction"], split["validation_fraction"])
    hours = part_hours(df, split["train_fraction"], split["validation_fraction"])

    print("Reglas: ajustando umbrales sin mirar test…", flush=True)
    before_test = part != TEST
    scores = rule_scores(
        df[before_test],
        rules_cfg["window_seconds"],
        rules_cfg["brute_force_ports"],
        rules_cfg["brute_force_max_duration_seconds"],
        group_by=part[before_test],
    )
    tuned = tune_thresholds(
        scores, df.loc[before_test, "is_attack"], hours[TRAIN] + hours[VALIDATION], budget
    )
    _compare_rule_thresholds(tuned, rules_cfg["thresholds"])
    train, validation = fit_and_threshold_sets(df, part)
    del df, scores  # el día completo ya no hace falta: libera memoria antes de entrenar
    gc.collect()

    models_dir = project_path(config, "models")
    models_dir.mkdir(parents=True, exist_ok=True)
    for name, estimator in (
        ("lightgbm", make_lightgbm(config["model"], seed, config["n_jobs"])),
        ("logistic_regression", make_logistic(seed)),
    ):
        print(f"Entrenando {name} con {len(train):,} flujos…", flush=True)
        clf = FlowClassifier(name, estimator).fit(train, validation, hours[VALIDATION], budget)
        joblib.dump(clf, models_dir / f"{name}.joblib")
        print(f"  umbral elegido en validación: {clf.threshold_!r}", flush=True)
        del clf
        gc.collect()


def _compare_rule_thresholds(tuned: dict, configured: dict) -> None:
    for rule, value in tuned.items():
        print(f"  {rule}: {value!r}", flush=True)
    same = all(
        configured.get(r) is not None and math.isclose(v, configured[r], rel_tol=1e-6)
        for r, v in tuned.items()
    )
    if not same:
        print(
            "AVISO: los umbrales de config/config.yaml (rules.thresholds) no coinciden con los "
            "calculados. Cópialos al config antes de `make evaluate`."
        )


if __name__ == "__main__":
    main()
