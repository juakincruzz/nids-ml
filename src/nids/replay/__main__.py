"""`make replay`: precalcula la reproducción de la parte de test de cada día (uno a uno)."""

import gc

import joblib

from nids.config import load_config, project_path
from nids.replay.build import build_day, replay_dir


def main() -> None:
    config = load_config()
    clf = joblib.load(project_path(config, "models") / "lightgbm.joblib")
    out_dir = replay_dir(config)
    out_dir.mkdir(parents=True, exist_ok=True)
    for day in config["dataset"]["cicids2017"]["days"]:
        flows = build_day(config, day, clf)
        flows.to_parquet(out_dir / f"{day}.parquet", index=False)
        print(
            f"{day}: {len(flows):,} flujos de test, {int(flows['model_flagged'].sum()):,} alertas "
            f"del modelo, {int(flows['rules_flagged'].sum()):,} de las reglas",
            flush=True,
        )
        del flows
        gc.collect()


if __name__ == "__main__":
    main()
