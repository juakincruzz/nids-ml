"""Escritura de los resúmenes de reports/."""

import json
import math
from pathlib import Path

import numpy as np


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(_to_json(obj), indent=2, ensure_ascii=False), encoding="utf-8")


def _to_json(obj):
    """Tipos de NumPy a Python y NaN/infinito a null (JSON no los admite)."""
    if isinstance(obj, dict):
        return {str(k): _to_json(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_to_json(v) for v in obj]
    if isinstance(obj, np.generic):
        obj = obj.item()
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj
