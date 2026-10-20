"""Tests de la unificación de etiquetas y de las familias."""

import pytest

from nids.data.labels import ATTACK_FAMILIES, BENIGN, FAMILY_OF, parse_label


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("BENIGN", BENIGN),
        ("Web Attack - Brute Force", "Web Attack - Brute Force"),
        # Variantes del CIC-IDS2017 original.
        ("Web Attack � Brute Force", "Web Attack - Brute Force"),
        ("Web Attack – Sql Injection", "Web Attack - SQL Injection"),
        ("Web Attack � XSS", "Web Attack - XSS"),
        ("PortScan", "Portscan"),
        ("Bot", "Botnet"),
        ("DoS slowloris", "DoS Slowloris"),
        ("  SSH-Patator ", "SSH-Patator"),
    ],
)
def test_unifica_variantes(raw, canonical):
    assert parse_label(raw) == (canonical, False)


def test_detecta_attempted():
    assert parse_label("DoS Hulk - Attempted") == ("DoS Hulk", True)
    assert parse_label("Web Attack - XSS - Attempted") == ("Web Attack - XSS", True)


def test_etiqueta_desconocida_falla_en_vez_de_ser_benigna():
    with pytest.raises(ValueError, match="desconocida"):
        parse_label("Ransomware")


def test_todas_las_etiquetas_tienen_familia_valida():
    families = set(FAMILY_OF.values())
    assert families == {"benign", *ATTACK_FAMILIES}


def test_el_escaneo_desde_la_maquina_infectada_es_escaneo():
    # Si fuera «infiltration», dejar fuera «scan» no quitaría todos los escaneos de train.
    assert FAMILY_OF["Infiltration - Portscan"] == "scan"
