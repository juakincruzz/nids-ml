"""Métricas con casos calculados a mano."""

import math

import numpy as np
import pytest

from nids.evaluation.metrics import (
    choose_threshold,
    detection_metrics,
    false_alarms_per_hour,
    metrics_by_family,
)

# 3 ataques y 5 normales. El detector acierta 2 ataques y marca 1 normal.
IS_ATTACK = np.array([1, 1, 1, 0, 0, 0, 0, 0], bool)
FLAGGED = np.array([1, 1, 0, 1, 0, 0, 0, 0], bool)


def test_falsas_alarmas_por_hora():
    # 1 falsa alarma en media hora -> 2 por hora.
    assert false_alarms_per_hour(IS_ATTACK, FLAGGED, hours=0.5) == 2.0


def test_metricas_binarias():
    m = detection_metrics(IS_ATTACK, FLAGGED, hours=0.5)
    assert (m["true_positives"], m["false_positives"]) == (2, 1)
    assert (m["false_negatives"], m["true_negatives"]) == (1, 4)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(1 / 5)
    assert m["false_alarms_per_hour"] == 2.0
    assert m["accuracy"] == pytest.approx(6 / 8)
    assert m["accuracy_always_normal"] == pytest.approx(5 / 8)
    assert math.isnan(m["pr_auc"])  # sin puntuación no hay curva


def test_umbral_respeta_el_presupuesto_y_solo_mira_los_normales():
    is_attack = np.array([0, 0, 0, 0, 1, 1], bool)
    score = np.array([0.9, 0.5, 0.4, 0.1, 0.95, 0.2])
    # 2 h con 1 falsa alarma/h -> se permiten 2 normales marcados: los de 0,9 y 0,5.
    t = choose_threshold(is_attack, score, hours=2, max_false_alarms_per_hour=1)
    assert t == 0.4
    assert np.sum((score > t) & ~is_attack) == 2

    # Las puntuaciones de los ataques no cambian el umbral.
    score_changed = score.copy()
    score_changed[is_attack] = [0.0, 0.0]
    assert choose_threshold(is_attack, score_changed, 2, 1) == t


def test_umbral_sin_presupuesto_no_marca_ningun_normal():
    is_attack = np.array([0, 0, 1], bool)
    score = np.array([0.3, 0.7, 0.9])
    t = choose_threshold(is_attack, score, hours=1, max_false_alarms_per_hour=0)
    assert t == 0.7
    assert not np.any((score > t) & ~is_attack)


def test_metricas_por_familia():
    family = np.array(["scan", "scan", "dos", "benign", "benign"], dtype=object)
    flagged = np.array([1, 1, 0, 1, 0], bool)
    predicted = np.array(["scan", "dos", "benign", "scan", "benign"], dtype=object)
    m = metrics_by_family(family, flagged, predicted)
    # Los dos escaneos se detectan (aunque uno se atribuya a DoS): recall 1.
    assert m["scan"]["recall"] == 1.0
    # Alertas con familia «scan»: un escaneo y un normal -> precisión 0,5.
    assert m["scan"]["precision"] == 0.5
    assert m["dos"]["recall"] == 0.0
    # Alertas con familia «dos»: una, que era un escaneo -> precisión 0.
    assert m["dos"]["precision"] == 0.0
