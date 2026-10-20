"""Gráficos estáticos de reports/ (matplotlib, PNG).

Colores: los tres primeros de una paleta validada para daltonismo; «siempre normal» en gris.
Cada barra lleva su valor escrito, así que nada depende solo del color.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import precision_recall_curve  # noqa: E402

COLORS = {
    "lightgbm": "#2a78d6",
    "logistic_regression": "#eb6834",
    "rules": "#1baf7a",
    "always_normal": "#8a8984",
    # Protocolo «ataques nuevos» (nunca aparecen junto a la regresión logística).
    "lightgbm_lofo": "#2a78d6",
    "isolation_forest": "#eb6834",
    # Protocolo «otra red».
    "cic_to_unsw": "#2a78d6",
    "unsw_to_unsw": "#1baf7a",
}
NAMES = {
    "lightgbm": "LightGBM",
    "logistic_regression": "Regresión logística",
    "rules": "Reglas de umbral",
    "always_normal": "Siempre normal",
    "lightgbm_lofo": "LightGBM sin esa familia",
    "isolation_forest": "Isolation Forest (solo normal)",
    "cic_to_unsw": "Entrenado en CIC-IDS2017",
    "unsw_to_unsw": "Entrenado en UNSW-NB15 (techo)",
}
FAMILY_NAMES = {
    "dos": "DoS/DDoS",
    "brute_force": "Fuerza bruta",
    "scan": "Escaneo",
    "web": "Web",
    "botnet": "Botnet",
    "infiltration": "Infiltración",
    "heartbleed": "Heartbleed",
}


def _style(ax):
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color("#8a8984")
    ax.grid(axis="y", color="#e5e4e0", linewidth=0.8)
    ax.set_axisbelow(True)


def plot_pr_curves(is_attack, detectors: dict, out: Path, title: str) -> None:
    """Curvas PR de los detectores con puntuación; las reglas, como un punto."""
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    for name, det in detectors.items():
        color = COLORS[name]
        if name == "always_normal":
            prevalence = np.mean(is_attack)
            ax.axhline(prevalence, color=color, linestyle="--", linewidth=1.5)
            ax.annotate(
                f"{NAMES[name]} (precisión = proporción de ataques)",
                (0.02, prevalence),
                textcoords="offset points",
                xytext=(0, 5),
                fontsize=8,
                color="#52514e",
            )
            continue
        point = (det["metrics"]["recall"], det["metrics"]["precision"])
        if det.get("score") is not None:
            precision, recall, _ = precision_recall_curve(is_attack, det["score"])
            label = f"{NAMES[name]} (PR-AUC {det['metrics']['pr_auc']:.3f})"
            ax.plot(recall, precision, color=color, linewidth=2, label=label)
        else:
            label = NAMES[name]
        # Punto de trabajo con el umbral elegido sin mirar test.
        ax.plot(
            *point,
            marker="o",
            markersize=9,
            color=color,
            markeredgecolor="white",
            linestyle="none",
            label=None if det.get("score") is not None else label,
        )
    ax.set_xlabel("Recall (ataques detectados)")
    ax.set_ylabel("Precisión (alertas que son ataques)")
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.02)
    ax.set_title(title + "\n(círculo = punto de trabajo con el umbral elegido)", fontsize=10)
    ax.legend(loc="lower left", fontsize=8, frameon=False)
    _style(ax)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def plot_recall_by_family(
    by_family: dict, out: Path, title: str, family_names: dict[str, str] = FAMILY_NAMES
) -> None:
    """Recall por familia para cada detector (barras agrupadas con el valor escrito)."""
    detectors = [d for d in by_family if d != "always_normal"]
    families = [
        f for f in family_names if any(by_family[d].get(f, {}).get("n_flows", 0) for d in detectors)
    ]
    x = np.arange(len(families))
    width = 0.8 / len(detectors)
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    for i, name in enumerate(detectors):
        values = [by_family[name][f]["recall"] for f in families]
        bars = ax.bar(
            x + (i - (len(detectors) - 1) / 2) * width,
            values,
            width * 0.92,
            color=COLORS[name],
            label=NAMES[name],
        )
        for bar, v in zip(bars, values, strict=True):
            ax.annotate(
                f"{v:.2f}",
                (bar.get_x() + bar.get_width() / 2, v),
                textcoords="offset points",
                xytext=(0, 2),
                ha="center",
                fontsize=7,
                color="#52514e",
            )
    n_flows = [by_family[detectors[0]][f]["n_flows"] for f in families]
    ax.set_xticks(
        x,
        [
            f"{family_names[f]}\n(n={n:,})".replace(",", " ")
            for f, n in zip(families, n_flows, strict=True)
        ],
        fontsize=8,
    )
    ax.set_ylabel("Recall")
    ax.set_ylim(0, 1.1)
    ax.set_title(title, fontsize=10)
    ax.legend(
        fontsize=8,
        frameon=False,
        ncols=len(detectors),
        loc="upper center",
        bbox_to_anchor=(0.5, -0.18),
    )
    _style(ax)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def plot_global_importance(table, out: Path, title: str) -> None:
    """Barras horizontales: contribución media (en valor absoluto) de cada variable."""
    table = table.iloc[::-1]  # la más importante arriba
    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    bars = ax.barh(
        [f"{name}\n({feature})" for feature, name in zip(table.index, table["name"], strict=True)],
        table["mean_abs_contribution"],
        color=COLORS["lightgbm"],
        height=0.7,
    )
    for bar, v in zip(bars, table["mean_abs_contribution"], strict=True):
        ax.annotate(
            f"{v:.2f}".replace(".", ","),
            (v, bar.get_y() + bar.get_height() / 2),
            textcoords="offset points",
            xytext=(3, 0),
            va="center",
            fontsize=7,
            color="#52514e",
        )
    ax.tick_params(axis="y", labelsize=7)
    ax.set_xlabel("Contribución media a las log-odds de la alerta (|SHAP|)")
    ax.set_title(title, fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="x", color="#e5e4e0", linewidth=0.8)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
