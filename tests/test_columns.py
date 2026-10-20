"""Que ninguna columna que delata la respuesta llegue al modelo."""

import pandas as pd
import pytest

from nids.data.clean import TrainCleaner, load_raw_day
from nids.features.columns import (
    METADATA_COLUMNS,
    assert_no_forbidden,
    feature_columns,
    forbidden_in,
)


@pytest.fixture(scope="module")
def processed(raw_sample_path):
    df, _ = load_raw_day(raw_sample_path, "monday")
    return df


def test_las_variables_del_modelo_no_incluyen_metadatos(processed):
    features = feature_columns(processed)
    assert forbidden_in(features) == []
    assert not set(features) & set(METADATA_COLUMNS)


def test_lo_que_sale_del_cleaner_tampoco(processed):
    X = TrainCleaner().fit(processed).transform(processed)
    assert forbidden_in(X.columns) == []


def test_el_puerto_de_destino_si_es_una_variable(processed):
    assert "Dst Port" in feature_columns(processed)
    assert "src_port" not in feature_columns(processed)


@pytest.mark.parametrize(
    "name",
    [
        "id",
        "Flow ID",
        "Src IP",
        " Source IP",
        "Destination IP",
        "dst_ip",
        "Src Port",
        " Source Port",
        "Timestamp",
        "Label",
        "label_raw",
        "Attempted Category",
        "family",
    ],
)
def test_detecta_columnas_prohibidas_escritas_de_cualquier_forma(name):
    with pytest.raises(ValueError, match="prohibidas"):
        assert_no_forbidden(["Flow Duration", name])


def test_feature_columns_falla_si_se_cuela_una_columna_nueva():
    # Una columna prohibida que no está en METADATA_COLUMNS no pasa desapercibida.
    df = pd.DataFrame({"Flow Duration": [1.0], "Source IP": ["10.0.0.1"]})
    with pytest.raises(ValueError, match="Source IP"):
        feature_columns(df)
