"""Protocolo «otra red»: entrenar con CIC-IDS2017 y probar con UNSW-NB15.

Solo se usan las 10 variables que significan lo mismo en los dos extractores de flujos
(nids.data.unsw.COMMON_FEATURES) y solo flujos TCP/UDP. Tres medidas:

- cic_to_unsw: LightGBM binario entrenado con CIC-IDS2017 (todo lo anterior al corte, umbral
  con el tráfico normal de validación de CIC) y evaluado en TODO UNSW-NB15. Es el protocolo.
- cic_to_cic: el mismo modelo en el test de CIC-IDS2017. Separa lo que se pierde por quedarse
  con 10 variables de lo que se pierde por cambiar de red.
- unsw_to_unsw: un LightGBM entrenado dentro de UNSW-NB15 con las mismas variables y el mismo
  reparto temporal (70/30 por sesión de captura). Es el techo de lo alcanzable con esas 10
  variables en esa red.

El umbral de cada modelo se elige con su propia validación (presupuesto de falsas alarmas por
hora), nunca mirando el conjunto en el que se evalúa.
"""

import gc

import pandas as pd

from nids.config import project_path
from nids.data.load import load_processed
from nids.data.unsw import COMMON_FEATURES, processed_path
from nids.evaluation.metrics import detection_metrics
from nids.evaluation.novel_attacks import family_result
from nids.evaluation.plots import plot_recall_by_family
from nids.evaluation.report import write_json
from nids.evaluation.split import (
    TEST,
    VALIDATION,
    fit_and_threshold_sets,
    part_hours,
    temporal_split,
)
from nids.models.classifiers import FlowClassifier, make_lightgbm

META = ["timestamp", "day", "family", "is_attack"]

UNSW_CATEGORIES = {
    "generic": "Generic",
    "exploits": "Exploits",
    "fuzzers": "Fuzzers",
    "reconnaissance": "Reconnaissance",
    "dos": "DoS",
    "shellcode": "Shellcode",
    "analysis": "Analysis",
    "backdoor": "Backdoor",
    "worms": "Worms",
}


def session_hours(df: pd.DataFrame) -> float:
    """Horas reales cubiertas: suma de la duración de cada sesión (o día) de captura."""
    spans = df.groupby("day", observed=True)["timestamp"].agg(lambda t: t.max() - t.min())
    return float(spans.dt.total_seconds().sum() / 3600)


def evaluate(clf: FlowClassifier, df: pd.DataFrame, hours: float, families: list[str]) -> dict:
    """Métricas binarias y recall por familia de `clf` sobre `df`."""
    score, flagged, _ = clf.predict(df)
    is_attack = df["is_attack"].to_numpy()
    family = df["family"].astype(str).to_numpy()
    return {
        "threshold": clf.threshold_,
        "hours": hours,
        # La proporción de ataques es la PR-AUC de puntuar al azar: sin ella la PR-AUC no se lee.
        "metrics": detection_metrics(is_attack, flagged, hours, score)
        | {"prevalence": float(is_attack.mean())},
        "by_family": {
            f: family_result(f, family, ~is_attack, flagged, hours, score)
            for f in families
            if (family == f).any()
        },
    }


def train_binary(config: dict, df: pd.DataFrame) -> tuple[FlowClassifier, pd.Series, dict]:
    """LightGBM binario con el mismo reparto y la misma elección de umbral que el resto."""
    split = config["split"]
    part = temporal_split(df, split["train_fraction"], split["validation_fraction"])
    hours = part_hours(df, split["train_fraction"], split["validation_fraction"])
    fit, threshold = fit_and_threshold_sets(df, part)
    clf = FlowClassifier(
        "lightgbm_common",
        make_lightgbm(config["model"], config["seed"], config["n_jobs"]),
        binary=True,
    ).fit(fit, threshold, hours[VALIDATION], config["evaluation"]["max_false_alarms_per_hour"])
    return clf, part, hours


def run(config: dict) -> dict:
    path = processed_path(config)
    if not path.exists():
        raise FileNotFoundError("Faltan los datos de UNSW-NB15: ejecuta `make data-unsw`.")

    print("Otra red: LightGBM con las 10 variables comunes, entrenado en CIC-IDS2017…", flush=True)
    cic = load_processed(config, columns=COMMON_FEATURES + META)
    clf_cic, cic_part, cic_hours = train_binary(config, cic)
    cic_families = sorted(set(cic["family"].astype(str)) - {"benign"})
    cic_test = cic[(cic_part == TEST).to_numpy()]
    results = {"cic_to_cic": evaluate(clf_cic, cic_test, cic_hours[TEST], cic_families)}
    del cic, cic_test
    gc.collect()

    unsw = pd.read_parquet(path, columns=COMMON_FEATURES + META)
    unsw_families = list(UNSW_CATEGORIES)
    print("…evaluado en todo UNSW-NB15…", flush=True)
    results["cic_to_unsw"] = evaluate(clf_cic, unsw, session_hours(unsw), unsw_families)

    print("…y techo: entrenado dentro de UNSW-NB15.", flush=True)
    clf_unsw, unsw_part, unsw_hours = train_binary(config, unsw)
    unsw_test = unsw[(unsw_part == TEST).to_numpy()]
    results["unsw_to_unsw"] = evaluate(clf_unsw, unsw_test, unsw_hours[TEST], unsw_families)
    # El modelo de CIC en ese mismo test, para comparar con el techo en igualdad de condiciones.
    results["cic_to_unsw_same_test"] = evaluate(clf_cic, unsw_test, unsw_hours[TEST], unsw_families)
    counts = pd.crosstab(unsw["family"].astype(str), unsw_part.to_numpy())

    out_dir = project_path(config, "reports") / "other_network"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "protocol": "other_network",
        "features": COMMON_FEATURES,
        "max_false_alarms_per_hour": config["evaluation"]["max_false_alarms_per_hour"],
        "unsw_flows_per_family_and_part": counts.to_dict(orient="index"),
        "notes": [
            "Solo flujos TCP/UDP y solo las 10 variables con el mismo significado en los dos "
            "extractores (ver reports/data/unsw_summary.json para lo descartado).",
            "cic_to_unsw: entrenado en CIC-IDS2017, evaluado en todo UNSW-NB15.",
            "cic_to_unsw_same_test: el mismo modelo, en el mismo test que unsw_to_unsw.",
            "unsw_to_unsw: entrenado dentro de UNSW-NB15 (techo con estas variables).",
            "cic_to_cic: el mismo modelo de CIC en el test de CIC (coste de usar 10 variables).",
        ],
        "detectors": results,
    }
    write_json(out_dir / "summary.json", summary)
    rows = []
    for name, r in results.items():
        rows.append({"detector": name, "scope": "all"} | r["metrics"])
        rows += [{"detector": name, "scope": f} | m for f, m in r["by_family"].items()]
    pd.DataFrame(rows).to_csv(out_dir / "metrics.csv", index=False)
    plot_recall_by_family(
        {
            "cic_to_unsw": results["cic_to_unsw_same_test"]["by_family"],
            "unsw_to_unsw": results["unsw_to_unsw"]["by_family"],
        },
        out_dir / "recall_by_category.png",
        "Otra red: recall por categoría de UNSW-NB15 (mismo test, 10 variables comunes)",
        family_names=UNSW_CATEGORIES,
    )
    return summary
