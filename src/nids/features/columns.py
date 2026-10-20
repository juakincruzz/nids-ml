"""Qué columnas puede usar el modelo y cuáles no.

Los datos procesados guardan columnas de metadatos (IPs, marca de tiempo, etiquetas…) porque las
necesitan las reglas clásicas, el reparto temporal y el panel. El modelo no debe verlas nunca:
delatan la respuesta (en CIC-IDS2017 el atacante tiene IPs fijas y los ataques, horas fijas).

Puertos:
- `Dst Port` SÍ es una variable: indica el servicio atacado (21, 22, 80…) y un IDS real lo ve.
- `src_port` NO: casi siempre es un puerto efímero que elige el sistema operativo; como mucho
  aprendería manías de la herramienta de ataque concreta, no el ataque.

Las comprobaciones comparan nombres normalizados («Source IP», « Src IP» y «src_ip» son lo mismo)
para que una columna prohibida no se cuele por venir escrita de otra forma.
"""

import re
from collections.abc import Iterable

import pandas as pd

# Columnas de metadatos de los Parquet procesados (ver nids.data.clean).
METADATA_COLUMNS = (
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "timestamp",
    "day",
    "label",
    "label_raw",
    "attempted_category",
    "family",
    "is_attack",
)

_FORBIDDEN_KEYS = {
    "id",
    "flowid",
    "srcip",
    "sourceip",
    "dstip",
    "destinationip",
    "srcport",
    "sourceport",
    "timestamp",
    "day",
    "label",
    "labelraw",
    "attemptedcategory",
    "family",
    "isattack",
}


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def forbidden_in(columns: Iterable[str]) -> list[str]:
    """Columnas de `columns` que el modelo no puede usar."""
    return [c for c in columns if _key(c) in _FORBIDDEN_KEYS or _key(c).endswith("ip")]


def assert_no_forbidden(columns: Iterable[str]) -> None:
    leaked = forbidden_in(columns)
    if leaked:
        raise ValueError(f"Columnas prohibidas entre las variables del modelo: {leaked}")


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Variables candidatas para el modelo: todo lo que no es metadato, comprobado."""
    columns = [c for c in df.columns if c not in METADATA_COLUMNS]
    assert_no_forbidden(columns)
    return columns
