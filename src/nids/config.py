"""Carga y validación de config/config.yaml, y semillas para la reproducibilidad."""

import random
from pathlib import Path
from typing import Any

import numpy as np
import yaml

# src/nids/config.py -> la raíz del repositorio está dos niveles por encima de src/.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"

REQUIRED_SECTIONS = (
    "seed",
    "n_jobs",
    "paths",
    "dataset",
    "split",
    "model",
    "anomaly",
    "evaluation",
    "rules",
    "web",
)


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Lee el YAML de configuración y comprueba que tiene sentido antes de usarlo."""
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    """Falla pronto y con un mensaje claro si falta algo o hay un valor imposible."""
    missing = [section for section in REQUIRED_SECTIONS if section not in config]
    if missing:
        raise ValueError(f"Faltan secciones en la configuración: {missing}")

    if not isinstance(config["seed"], int):
        raise ValueError("La semilla (seed) tiene que ser un entero.")

    for key in ("train_fraction", "validation_fraction"):
        value = config["split"].get(key)
        if not isinstance(value, int | float) or not 0 < value < 1:
            raise ValueError(f"split.{key} tiene que estar entre 0 y 1 (sin incluirlos): {value}")


def project_path(config: dict[str, Any], key: str) -> Path:
    """Devuelve la ruta absoluta de una entrada de `paths` (relativa a la raíz del repo)."""
    return PROJECT_ROOT / config["paths"][key]


def set_seeds(seed: int) -> None:
    """Fija las semillas globales de Python y NumPy.

    No basta por sí solo: a cada modelo se le pasa además `random_state=seed`.
    """
    random.seed(seed)
    np.random.seed(seed)  # noqa: NPY002 (algunas librerías aún usan el generador global)
