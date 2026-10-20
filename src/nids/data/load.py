"""Carga de los Parquet procesados por `make data`."""

import pandas as pd
import pyarrow.parquet as pq

from nids.config import project_path

# Columnas de texto que ningún paso de la evaluación necesita: no se cargan, para ahorrar memoria.
_NOT_LOADED = {"flow_id", "label_raw", "attempted_category"}


def load_processed(config: dict, days: list[str] | None = None) -> pd.DataFrame:
    """Une los días pedidos (todos por defecto) en un único DataFrame ordenado por tiempo."""
    days = days or config["dataset"]["cicids2017"]["days"]
    processed_dir = project_path(config, "processed_data")
    missing = [d for d in days if not (processed_dir / f"{d}.parquet").exists()]
    if missing:
        raise FileNotFoundError(f"Faltan datos procesados de {missing}: ejecuta `make data`.")

    schema = pq.read_schema(processed_dir / f"{days[0]}.parquet")
    columns = [c for c in schema.names if c not in _NOT_LOADED]
    df = pd.concat(
        [pd.read_parquet(processed_dir / f"{d}.parquet", columns=columns) for d in days],
        ignore_index=True,
    )
    # Al unir días las categorías difieren y pandas las pasa a texto; se vuelven a categorizar
    # (2 millones de cadenas repetidas ocupan mucho más que una categoría).
    for col in ("day", "family", "label", "src_ip", "dst_ip"):
        df[col] = df[col].astype("category")
    return df
