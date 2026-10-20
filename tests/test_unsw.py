"""UNSW-NB15: alineación con las variables y unidades de CIC-IDS2017 (datos sintéticos)."""

import numpy as np
import pandas as pd
import pytest

from nids.data.clean import clean_values
from nids.data.unsw import COMMON_FEATURES, align, file_url, parse_port
from nids.evaluation.other_network import session_hours
from nids.features.columns import feature_columns

T0 = pd.Timestamp("2015-01-22 12:00", tz="UTC").timestamp()


@pytest.fixture
def raw():
    rows = [
        # dsport, proto, dur, Spkts, Dpkts, Sintpkt, Dintpkt, Stime, attack_cat, Label
        ("80", "tcp", 1.5, 10, 5, 2.0, 4.0, T0, None, 0),
        ("0xcc09", "udp", 0.5, 3, 1, 0.0, 0.0, T0 + 10, " Backdoors ", 1),
        ("-", "tcp", 0.0, 2, 0, 0.0, 0.0, T0 + 20, "Exploits", 1),
        ("0", "arp", 0.1, 1, 1, 0.0, 0.0, T0 + 30, "DoS", 1),  # no es TCP/UDP: fuera
        # Segunda sesión de captura, 27 días después.
        ("53", "udp", 0.001, 1, 1, 0.0, 0.0, T0 + 27 * 86400, "Generic", 1),
        ("53", "udp", 0.001, 1, 1, 0.0, 0.0, T0 + 27 * 86400 + 3600, None, 0),
    ]
    columns = ["dsport", "proto", "dur", "Spkts", "Dpkts", "Sintpkt", "Dintpkt", "Stime"]
    return pd.DataFrame(rows, columns=[*columns, "attack_cat", "Label"])


def test_puertos_decimales_hexadecimales_y_vacios():
    port = parse_port(pd.Series(["80", "0xcc09", "-", " 443 "]))
    assert port.iloc[0] == 80 and port.iloc[1] == 0xCC09 and port.iloc[3] == 443
    assert np.isnan(port.iloc[2])


def test_unidades_y_nombres_de_cic(raw):
    df, _ = align(raw, "Australia/Sydney")
    first = df.iloc[0]
    assert first["Flow Duration"] == 1.5e6  # s -> µs
    assert first["Fwd IAT Mean"] == 2000 and first["Bwd IAT Mean"] == 4000  # ms -> µs
    assert first["Flow Packets/s"] == pytest.approx(15 / 1.5)
    assert first["Protocol"] == 6 and first["Dst Port"] == 80
    # Las variables del modelo son justo las comunes, sin columnas prohibidas.
    assert feature_columns(df) == COMMON_FEATURES


def test_solo_tcp_udp_y_se_cuenta_lo_descartado(raw):
    df, stats = align(raw, "Australia/Sydney")
    assert len(df) == 5
    assert stats["rows_not_tcp_udp_dropped"] == 1
    assert stats["attacks_not_tcp_udp_dropped"] == 1


def test_categorias_unificadas(raw):
    df, _ = align(raw, "Australia/Sydney")
    assert list(df["family"]) == ["benign", "backdoor", "exploits", "generic", "benign"]
    assert list(df["label"])[:2] == ["BENIGN", "Backdoor"]
    assert df["is_attack"].sum() == 3


def test_sesiones_de_captura_y_horas(raw):
    df, stats = align(raw, "Australia/Sydney")
    # 12:00 UTC = 23:00 en Sídney (UTC+11 en enero).
    assert list(stats["sessions"]) == ["unsw_2015-01-22", "unsw_2015-02-18"]
    # Primera sesión: 20 s entre el primer y el último flujo TCP/UDP; segunda: 1 h.
    assert session_hours(df) == pytest.approx(20 / 3600 + 1)


def test_duracion_cero_da_infinito_y_la_limpieza_lo_pasa_a_nan(raw):
    df, _ = align(raw, "Australia/Sydney")
    df, stats = clean_values(df)
    assert np.isnan(df.loc[2, "Flow Packets/s"])
    # Flujo con duración 0: 2/0 y 2/0 son infinitos; los paquetes de vuelta son 0/0 = NaN.
    assert stats["infinite_to_nan"] == 2
    assert np.isnan(df.loc[2, "Bwd Packets/s"])


def test_url_de_la_api_de_sharepoint():
    url = file_url("https://x.sharepoint.com/personal/u", "/personal/u/Documents/A B", "f.csv")
    assert url == (
        "https://x.sharepoint.com/personal/u/_api/web/"
        "GetFileByServerRelativeUrl('/personal/u/Documents/A%20B/f.csv')/$value"
    )
