"""`make evaluate`: ejecuta los protocolos de evaluación y escribe reports/."""

from nids.config import load_config
from nids.evaluation import known_attacks


def main() -> None:
    config = load_config()
    summary = known_attacks.run(config)
    print(f"Ataques conocidos: {summary['hours']['test']:.1f} h de test")
    for name, det in summary["detectors"].items():
        m = det["metrics"]
        print(
            f"  {name:20s} recall {m['recall']:.3f}  precisión {m['precision']:.3f}  "
            f"falsas alarmas/h {m['false_alarms_per_hour']:.1f}  PR-AUC {m['pr_auc']:.3f}"
        )


if __name__ == "__main__":
    main()
