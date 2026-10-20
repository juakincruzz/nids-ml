"""Limpieza de CIC-IDS2017 en dos niveles.

1. `load_raw_day`: limpieza fila a fila que no depende de otros datos y se puede hacer antes del
   reparto (tipos, orden temporal, etiquetas, infinitos y negativos imposibles a NaN, filas
   repetidas por error). Es lo que se guarda en Parquet.
2. `TrainCleaner`: todo lo que se *aprende* de los datos (columnas constantes, medianas para
   rellenar NaN). Se ajusta solo con train y se aplica igual a validación y test.

Duplicados: se eliminan las filas idénticas en todo (salvo `id`), que serían errores de
exportación; en la versión corregida no hay ninguna. Los flujos con las mismas *variables* pero
distinta hora o IP se conservan: son conexiones reales distintas (p. ej., consultas DNS
repetidas) y quitarlas falsearía el recuento de falsas alarmas por hora.
"""

from pathlib import Path
from typing import Any, Self

import numpy as np
import pandas as pd

from nids.data.labels import BENIGN, FAMILY_OF, parse_label
from nids.features.columns import feature_columns

_RENAMES = {
    "Flow ID": "flow_id",
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dst_ip",
    "Timestamp": "timestamp",
    "Label": "label_raw",
    "Attempted Category": "attempted_category",
}

# Variables en las que -1 es un valor legítimo («no es ICMP»). En el resto, un negativo es un
# error de CICFlowMeter (p. ej., longitudes de cabecera negativas) y se trata como desconocido.
_SIGNED_FEATURES = {"ICMP Code", "ICMP Type"}


def load_raw_day(path: Path, day: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Lee el CSV de un día y aplica la limpieza fila a fila. Devuelve (datos, estadísticas)."""
    df = pd.read_csv(path, engine="pyarrow")
    stats: dict[str, Any] = {"rows_raw": len(df)}

    df = df.drop(columns=["id"]).rename(columns=_RENAMES)
    before = len(df)
    df = df.drop_duplicates()
    stats["exact_duplicates_dropped"] = before - len(df)

    # Las marcas de tiempo de esta versión están en UTC (el laboratorio estaba en UTC-3).
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601").dt.tz_localize("UTC")
    # Los CSV no vienen ordenados por tiempo, y el reparto temporal lo necesita.
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df["day"] = day

    df, label_stats = add_labels(df)
    df, value_stats = clean_values(df)
    stats |= label_stats | value_stats
    stats["rows"] = len(df)
    return df, stats


def add_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Añade `label` (canónica), `family` e `is_attack`. Los «Attempted» pasan a benignos."""
    parsed = {raw: parse_label(raw) for raw in df["label_raw"].unique()}
    canonical = df["label_raw"].map(lambda raw: parsed[raw][0])
    attempted = df["label_raw"].map(lambda raw: parsed[raw][1]) | (df["attempted_category"] != -1)

    df["label"] = canonical.where(~attempted, BENIGN)
    df["family"] = df["label"].map(FAMILY_OF)
    df["is_attack"] = df["family"] != "benign"
    for col in ("day", "label", "label_raw", "family"):
        df[col] = df[col].astype("category")
    return df, {"attempted_relabelled_benign": int(attempted.sum())}


def clean_values(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Infinitos y negativos imposibles -> NaN; todas las variables a float32."""
    features = feature_columns(df)
    X = df[features].astype("float64")

    infinite = np.isinf(X)
    X = X.mask(infinite)
    unsigned = [c for c in features if c not in _SIGNED_FEATURES]
    negative = X[unsigned] < 0
    X[unsigned] = X[unsigned].mask(negative)

    df[features] = X.astype("float32")
    return df, {
        "infinite_to_nan": int(infinite.to_numpy().sum()),
        "negative_to_nan": int(negative.to_numpy().sum()),
    }


class TrainCleaner:
    """Limpieza que se aprende de los datos. `fit` solo debe recibir train."""

    def fit(self, train: pd.DataFrame) -> Self:
        features = feature_columns(train)
        n_distinct = train[features].nunique(dropna=True)
        self.constant_columns_ = [c for c in features if n_distinct[c] <= 1]
        self.features_ = [c for c in features if c not in self.constant_columns_]
        self.medians_ = train[self.features_].median()
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Devuelve solo las variables del modelo, con los NaN rellenos con medianas de train."""
        return df[self.features_].fillna(self.medians_)
