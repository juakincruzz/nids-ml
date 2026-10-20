"""`make evaluate`: ejecuta los protocolos de evaluación y escribe reports/.

python -m nids.evaluation            # todos
python -m nids.evaluation known      # solo «ataques conocidos»
python -m nids.evaluation novel      # solo «ataques nuevos»
python -m nids.evaluation other      # solo «otra red» (necesita `make data-unsw`)

Con «all», «otra red» se salta (avisando) si no se han descargado los datos de UNSW-NB15.
"""

import argparse

from nids.config import load_config
from nids.data.unsw import processed_path
from nids.evaluation import known_attacks, novel_attacks, other_network


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "protocol", nargs="?", choices=("known", "novel", "other", "all"), default="all"
    )
    protocol = parser.parse_args().protocol
    config = load_config()

    if protocol in ("known", "all"):
        summary = known_attacks.run(config)
        print(f"Ataques conocidos: {summary['hours']['test']:.1f} h de test")
        for name, det in summary["detectors"].items():
            m = det["metrics"]
            print(
                f"  {name:20s} recall {m['recall']:.3f}  precisión {m['precision']:.3f}  "
                f"falsas alarmas/h {m['false_alarms_per_hour']:.1f}  PR-AUC {m['pr_auc']:.3f}"
            )

    if protocol in ("novel", "all"):
        summary = novel_attacks.run(config)
        print("Ataques nuevos (recall de la familia excluida | falsas alarmas/h):")
        for name, by_family in summary["detectors"].items():
            cells = "  ".join(
                f"{fam} {m['recall']:.2f}|{m['false_alarms_per_hour']:.0f}"
                for fam, m in by_family.items()
            )
            print(f"  {name:17s} {cells}")

    if protocol == "other" or (protocol == "all" and processed_path(config).exists()):
        summary = other_network.run(config)
        print("Otra red (10 variables comunes, solo TCP/UDP):")
        for name, det in summary["detectors"].items():
            m = det["metrics"]
            print(
                f"  {name:22s} recall {m['recall']:.3f}  precisión {m['precision']:.3f}  "
                f"falsas alarmas/h {m['false_alarms_per_hour']:.1f}  PR-AUC {m['pr_auc']:.3f}"
            )
    elif protocol == "all":
        print("Otra red: sin datos de UNSW-NB15 (`make data-unsw`); se salta.")


if __name__ == "__main__":
    main()
