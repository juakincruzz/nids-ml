"""Tests de la carga de configuración y de la reproducibilidad."""

import random

import numpy as np
import pytest
import yaml

from nids.config import PROJECT_ROOT, load_config, project_path, set_seeds


def test_config_real_es_valida():
    config = load_config()
    assert isinstance(config["seed"], int)
    assert 0 < config["split"]["train_fraction"] < 1


def test_las_rutas_son_relativas_a_la_raiz():
    config = load_config()
    assert project_path(config, "raw_data") == PROJECT_ROOT / "data" / "raw"


@pytest.mark.parametrize(
    ("section", "key", "bad_value"),
    [
        ("split", "train_fraction", 1.5),
        ("split", "validation_fraction", 0),
        (None, "seed", "42"),
    ],
)
def test_rechaza_valores_imposibles(tmp_path, section, key, bad_value):
    config = load_config()
    if section is None:
        config[key] = bad_value
    else:
        config[section][key] = bad_value
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(path)


def test_rechaza_secciones_que_faltan(tmp_path):
    config = load_config()
    del config["split"]
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    with pytest.raises(ValueError, match="split"):
        load_config(path)


def test_set_seeds_hace_reproducibles_los_aleatorios():
    set_seeds(42)
    first = (random.random(), np.random.rand(3))  # noqa: NPY002
    set_seeds(42)
    second = (random.random(), np.random.rand(3))  # noqa: NPY002

    assert first[0] == second[0]
    np.testing.assert_array_equal(first[1], second[1])
