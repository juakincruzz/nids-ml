"""Reparto temporal dentro de cada día. Nunca aleatorio.

Para cada día se toma su duración real (del primer al último flujo) y se corta por el tiempo:

    |------------- train -------------|-- validation --|------- test -------|
    0                  tf·(1−vf)                       tf                   1

con tf = `train_fraction` y vf = `validation_fraction`. La validación es la parte final de lo que
el protocolo llama «train»: sirve para elegir el umbral sin mirar test.

En la validación solo se usan los flujos NORMALES (ver `fit_and_threshold_sets`). El umbral
depende únicamente de cuántas falsas alarmas por hora da el tráfico normal, y los ataques de ese
tramo hacen falta para entrenar: todo el escaneo y el SSH-Patator anteriores al corte caen ahí, y
sin ellos el modelo no vería ni un solo escaneo.

Con tf = 0,7, web y botnet quedan solo antes del corte y Heartbleed solo después (ver
reports/known_attacks/summary.json). Es una decisión consciente: un único corte por día
garantiza que ningún flujo de test es anterior a uno de entrenamiento del mismo día.
"""

import numpy as np
import pandas as pd

TRAIN, VALIDATION, TEST = "train", "validation", "test"


def _day_position(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """Posición relativa de cada flujo dentro de su día (0 = primero, 1 = último) y duración."""
    by_day = df.groupby("day", observed=True)["timestamp"]
    start, end = by_day.transform("min"), by_day.transform("max")
    duration = end - start
    return (df["timestamp"] - start) / duration, duration


def temporal_split(
    df: pd.DataFrame, train_fraction: float, validation_fraction: float
) -> pd.Series:
    """Devuelve, para cada flujo, 'train', 'validation' o 'test'."""
    position, _ = _day_position(df)
    validation_start = train_fraction * (1 - validation_fraction)
    part = np.select(
        [position >= train_fraction, position >= validation_start],
        [TEST, VALIDATION],
        default=TRAIN,
    )
    return pd.Series(part, index=df.index, name="part")


def part_hours(df: pd.DataFrame, train_fraction: float, validation_fraction: float) -> dict:
    """Horas reales que cubre cada parte, sumando todos los días de `df`.

    Es el denominador de las falsas alarmas por hora: el tiempo del periodo, no el número de
    flujos.
    """
    durations = df.groupby("day", observed=True)["timestamp"].agg(lambda t: t.max() - t.min())
    total_hours = durations.dt.total_seconds().sum() / 3600
    return {
        TRAIN: total_hours * train_fraction * (1 - validation_fraction),
        VALIDATION: total_hours * train_fraction * validation_fraction,
        TEST: total_hours * (1 - train_fraction),
    }


def fit_and_threshold_sets(
    df: pd.DataFrame, part: pd.Series, exclude_family: str | None = None
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(conjunto para ajustar el modelo, conjunto para elegir el umbral). Ninguno toca test.

    - Ajuste: todo lo anterior al corte salvo el tráfico normal de validación y, si se pide,
      salvo una familia de ataque entera (protocolo «ataques nuevos»).
    - Umbral: el tráfico normal de validación (flujos que el modelo no ha visto).
    """
    is_attack = df["is_attack"].to_numpy()
    in_validation = (part == VALIDATION).to_numpy()
    fit_mask = (part == TRAIN).to_numpy() | (in_validation & is_attack)
    if exclude_family is not None:
        fit_mask &= df["family"].to_numpy() != exclude_family
    fit = df[fit_mask]
    threshold = df[in_validation & ~is_attack]
    return fit, threshold
