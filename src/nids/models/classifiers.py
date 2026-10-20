"""Clasificadores de flujos: el modelo principal (LightGBM) y la referencia lineal.

Los dos son multiclase sobre las familias vistas en train: así cada alerta lleva una familia.
La decisión de alertar es binaria: puntuación de ataque = log-odds de ataque frente a normal, y
se alerta si supera un umbral elegido en validación.

Desbalance: no se usan pesos de clase ni submuestreo. El umbral, elegido con un presupuesto de
falsas alarmas, ya decide cuánto se arriesga; los pesos «balanced» darían a las 12 muestras de
infiltración un peso unas 100 000 veces mayor que el del tráfico normal.
"""

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.special import logsumexp
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from nids.data.clean import TrainCleaner
from nids.evaluation.metrics import choose_threshold


def signed_log1p(X):
    """Comprime las colas largas (bytes/s llega a 10⁹) para que el modelo lineal no se ahogue."""
    X = np.asarray(X, dtype=np.float32)  # en float32 para no duplicar la memoria
    return np.sign(X) * np.log1p(np.abs(X))


def make_lightgbm(params: dict, seed: int, n_jobs: int = 4) -> lgb.LGBMClassifier:
    return lgb.LGBMClassifier(random_state=seed, n_jobs=n_jobs, verbose=-1, **params)


def make_logistic(seed: int):
    return make_pipeline(
        FunctionTransformer(signed_log1p),
        StandardScaler(),
        LogisticRegression(max_iter=300, random_state=seed),
    )


class FlowClassifier:
    """Limpieza ajustada con train + estimador + umbral elegido en validación.

    Sin parada temprana: la validación solo tiene tráfico normal (ver nids.evaluation.split),
    así que el número de árboles es el del config.

    Con `binary=True` aprende solo ataque frente a normal (protocolo «ataques nuevos»): las
    clases son «benign» y «attack».
    """

    def __init__(self, name: str, estimator, binary: bool = False):
        self.name = name
        self.estimator = estimator
        self.binary = binary

    def fit(
        self,
        train: pd.DataFrame,
        validation: pd.DataFrame,
        validation_hours: float,
        max_false_alarms_per_hour: float,
    ) -> "FlowClassifier":
        self.cleaner_ = TrainCleaner().fit(train)
        X = self.cleaner_.transform(train)
        if self.binary:
            self.classes_ = ["benign", "attack"]
            y = train["is_attack"].astype(int)
        else:
            # Familias -> enteros 0..k-1; `classes_` guarda el nombre de cada columna de logits.
            self.classes_ = sorted(train["family"].astype(str).unique())
            code = {family: i for i, family in enumerate(self.classes_)}
            y = train["family"].astype(str).map(code)

        self.estimator.fit(X, y)

        self.threshold_ = choose_threshold(
            validation["is_attack"].to_numpy(),
            self.attack_score(validation),
            validation_hours,
            max_false_alarms_per_hour,
        )
        return self

    def logits(self, df: pd.DataFrame) -> np.ndarray:
        """Logits por clase (una columna por familia de `classes_`)."""
        X = self.cleaner_.transform(df)
        if isinstance(self.estimator, lgb.LGBMClassifier):
            z = self.estimator.predict(X, raw_score=True)
        else:
            z = self.estimator.decision_function(X)
        # Con dos clases ambos devuelven un único logit (el de la clase 1): se completa.
        return np.column_stack([np.zeros_like(z), z]) if z.ndim == 1 else z

    def attack_score(self, df: pd.DataFrame, logits: np.ndarray | None = None) -> np.ndarray:
        """Log-odds de ataque: log P(ataque) − log P(normal).

        No se usa 1 − P(normal) porque en float64 se satura: si P(normal) < 1e-16, vale 1,0
        exacto, y miles de flujos empatan justo donde hay que poner el umbral. Las log-odds
        ordenan igual (es una transformación monótona) pero sin empates. Para enseñar una
        «confianza» entre 0 y 1 basta con aplicarles la sigmoide.
        """
        z = self.logits(df) if logits is None else logits
        benign = self.classes_.index("benign")
        attack = np.delete(z, benign, axis=1)
        return logsumexp(attack, axis=1) - z[:, benign]

    def predict(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Devuelve (puntuación de ataque, marcado, familia atribuida a cada flujo)."""
        z = self.logits(df)
        score = self.attack_score(df, z)
        flagged = score > self.threshold_
        attack_cols = [i for i, c in enumerate(self.classes_) if c != "benign"]
        best_attack = np.asarray(self.classes_, dtype=object)[
            np.array(attack_cols)[z[:, attack_cols].argmax(axis=1)]
        ]
        family = np.where(flagged, best_attack, "benign")
        return score, flagged, family
