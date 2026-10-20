"""Tests de la limpieza fila a fila y de la limpieza ajustada solo con train."""

import numpy as np
import pandas as pd
import pytest

from nids.data.clean import TrainCleaner, load_raw_day


@pytest.fixture(scope="module")
def loaded(raw_sample_path):
    return load_raw_day(raw_sample_path, "monday")


def _row(df, flow_id_suffix):
    """Fila cuyo Flow ID usa el puerto de origen 400NN (NN = id de la fila del fixture)."""
    return df[df["flow_id"].str.contains(f"-{40000 + flow_id_suffix}-")].iloc[0]


def test_ordena_por_tiempo_en_utc(loaded):
    df, _ = loaded
    assert df["timestamp"].is_monotonic_increasing
    assert str(df["timestamp"].dt.tz) == "UTC"


def test_elimina_solo_las_filas_repetidas_por_completo(loaded):
    df, stats = loaded
    assert stats["rows_raw"] == 10
    assert stats["exact_duplicates_dropped"] == 1
    # Las filas 1 y 10 tienen las mismas variables pero son flujos distintos: se quedan las dos.
    assert len(df) == 9 == stats["rows"]


def test_infinitos_y_negativos_imposibles_pasan_a_nan(loaded):
    df, stats = loaded
    assert np.isnan(_row(df, 1)["Flow Bytes/s"])
    assert np.isnan(_row(df, 2)["Fwd Header Length"])
    assert stats["infinite_to_nan"] == 4  # dos columnas en las filas 1 y 10
    assert stats["negative_to_nan"] == 1


def test_el_menos_uno_de_icmp_se_conserva(loaded):
    df, _ = loaded
    assert _row(df, 1)["ICMP Type"] == -1
    assert _row(df, 8)["ICMP Type"] == 8


def test_etiquetas_y_familias(loaded):
    df, stats = loaded
    attempted = _row(df, 5)
    assert attempted["label"] == "BENIGN"
    assert attempted["label_raw"] == "SSH-Patator - Attempted"
    assert not attempted["is_attack"]
    assert stats["attempted_relabelled_benign"] == 1

    assert _row(df, 6)["label"] == "Web Attack - Brute Force"
    assert _row(df, 6)["family"] == "web"
    assert _row(df, 7)["family"] == "scan"
    assert _row(df, 9)["family"] == "dos"
    assert df["is_attack"].sum() == 4


# --- TrainCleaner: lo que se aprende de los datos sale solo de train ---------------------------


@pytest.fixture
def train_test():
    train = pd.DataFrame(
        {
            "Flow Duration": [1.0, 2.0, 3.0, np.nan],
            "Flow Packets/s": [10.0, 10.0, 10.0, 10.0],  # constante en train
            "label": ["BENIGN"] * 4,
        }
    )
    test = pd.DataFrame(
        {
            "Flow Duration": [np.nan, 100.0, 200.0, 300.0],
            "Flow Packets/s": [1.0, 2.0, 3.0, 4.0],  # en test varía, pero se decide con train
            "label": ["BENIGN"] * 4,
        }
    )
    return train, test


def test_medianas_solo_de_train(train_test):
    train, test = train_test
    cleaner = TrainCleaner().fit(train)
    assert cleaner.medians_["Flow Duration"] == 2.0
    X_test = cleaner.transform(test)
    assert X_test["Flow Duration"].iloc[0] == 2.0  # mediana de train, no la de test (200)


def test_columnas_constantes_solo_de_train(train_test):
    train, test = train_test
    cleaner = TrainCleaner().fit(train)
    assert cleaner.constant_columns_ == ["Flow Packets/s"]
    assert list(cleaner.transform(test).columns) == ["Flow Duration"]


def test_transform_no_reajusta(train_test):
    train, test = train_test
    cleaner = TrainCleaner().fit(train)
    medians_before = cleaner.medians_.copy()
    cleaner.transform(test)
    pd.testing.assert_series_equal(cleaner.medians_, medians_before)
