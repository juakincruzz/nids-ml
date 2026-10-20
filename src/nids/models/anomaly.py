"""Detector de anomalías entrenado solo con tráfico normal (Isolation Forest).

No necesita ejemplos de ataque: aprende cómo es el tráfico normal y marca lo que se aparta.
Es la referencia natural para ataques que ningún clasificador ha visto.

Isolation Forest corta cada variable en un punto al azar entre su mínimo y su máximo. Con colas
tan largas (bytes/s llega a 10⁹) casi todos los cortes caerían en la cola, así que antes se
comprimen con la misma transformación logarítmica que usa la regresión logística.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer

from nids.data.clean import TrainCleaner
from nids.evaluation.metrics import choose_threshold
from nids.models.classifiers import signed_log1p


class AnomalyDetector:
    def __init__(self, n_estimators: int, max_samples: int, seed: int, n_jobs: int = 4):
        self.estimator = make_pipeline(
            FunctionTransformer(signed_log1p),
            IsolationForest(
                n_estimators=n_estimators,
                max_samples=max_samples,
                random_state=seed,
                n_jobs=n_jobs,
            ),
        )

    def fit(
        self,
        benign_train: pd.DataFrame,
        benign_validation: pd.DataFrame,
        validation_hours: float,
        max_false_alarms_per_hour: float,
    ) -> "AnomalyDetector":
        """Se ajusta y elige el umbral SOLO con tráfico normal: si llega un ataque, falla."""
        for name, df in (("train", benign_train), ("validación", benign_validation)):
            if df["is_attack"].any():
                raise ValueError(f"El detector de anomalías solo admite tráfico normal ({name}).")
        self.cleaner_ = TrainCleaner().fit(benign_train)
        self.estimator.fit(self.cleaner_.transform(benign_train))
        self.threshold_ = choose_threshold(
            benign_validation["is_attack"].to_numpy(),
            self.anomaly_score(benign_validation),
            validation_hours,
            max_false_alarms_per_hour,
        )
        return self

    def anomaly_score(self, df: pd.DataFrame) -> np.ndarray:
        """Cuanto más alto, más raro (score_samples de sklearn va al revés)."""
        return -self.estimator.score_samples(self.cleaner_.transform(df))

    def predict(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        score = self.anomaly_score(df)
        return score, score > self.threshold_
