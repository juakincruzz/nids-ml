"""Reparto temporal: ningún flujo de test es anterior a uno de train del mismo día."""

import pandas as pd
import pytest

from nids.evaluation.split import (
    TEST,
    TRAIN,
    VALIDATION,
    fit_and_threshold_sets,
    part_hours,
    temporal_split,
)


@pytest.fixture
def two_days():
    """Dos días de 101 flujos, uno por segundo durante 100 s, desordenados a propósito."""
    frames = []
    for day, start in (("monday", "2017-07-03 12:00"), ("tuesday", "2017-07-04 12:00")):
        ts = pd.date_range(start, periods=101, freq="1s", tz="UTC")
        frames.append(pd.DataFrame({"timestamp": ts, "day": day}))
    return pd.concat(frames).sample(frac=1, random_state=0).reset_index(drop=True)


def test_test_siempre_despues_de_train_en_cada_dia(two_days):
    part = temporal_split(two_days, 0.7, 0.2)
    for _, g in two_days.assign(part=part).groupby("day"):
        before_test = g.loc[g["part"] != TEST, "timestamp"]
        assert g.loc[g["part"] == TEST, "timestamp"].min() > before_test.max()
        # Y la validación es la parte final de lo anterior al corte.
        assert (
            g.loc[g["part"] == VALIDATION, "timestamp"].min()
            > g.loc[g["part"] == TRAIN, "timestamp"].max()
        )


def test_proporciones_por_tiempo(two_days):
    part = temporal_split(two_days, 0.7, 0.2)
    # Por día: segundos 0-55 train (56), 56-69 validación (14), 70-100 test (31).
    assert (part == TRAIN).sum() == 2 * 56
    assert (part == VALIDATION).sum() == 2 * 14
    assert (part == TEST).sum() == 2 * 31


def test_horas_de_cada_parte_calculadas_a_mano(two_days):
    hours = part_hours(two_days, 0.7, 0.2)
    total = 200 / 3600  # dos días de 100 s
    assert hours[TEST] == pytest.approx(0.3 * total)
    assert hours[VALIDATION] == pytest.approx(0.7 * 0.2 * total)
    assert hours[TRAIN] == pytest.approx(0.7 * 0.8 * total)


def test_conjuntos_de_ajuste_y_umbral(two_days):
    df = two_days.assign(is_attack=two_days.index % 3 == 0)
    part = temporal_split(df, 0.7, 0.2)
    fit, threshold = fit_and_threshold_sets(df, part)

    # Nada de test en ninguno de los dos, y no comparten flujos.
    assert not (part[fit.index] == TEST).any() and not (part[threshold.index] == TEST).any()
    assert not set(fit.index) & set(threshold.index)
    # El umbral se elige solo con tráfico normal de validación...
    assert (part[threshold.index] == VALIDATION).all() and not threshold["is_attack"].any()
    # ...y los ataques de validación sí se usan para entrenar.
    val_attacks = df.index[(part == VALIDATION) & df["is_attack"]]
    assert len(val_attacks) > 0 and set(val_attacks) <= set(fit.index)
