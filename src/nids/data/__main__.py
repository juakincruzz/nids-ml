"""`make data`: descarga, limpieza y Parquet de CIC-IDS2017 (versión corregida).

Deja un Parquet por día en data/processed/ y un resumen pequeño en reports/data/summary.json.
"""

import json

from nids.config import load_config, project_path
from nids.data.clean import load_raw_day
from nids.data.download import download, extract_csvs


def main() -> None:
    config = load_config()
    dataset = config["dataset"]["cicids2017"]
    raw_dir = project_path(config, "raw_data")
    processed_dir = project_path(config, "processed_data")
    processed_dir.mkdir(parents=True, exist_ok=True)

    zip_path = download(dataset["url"], raw_dir / "CICIDS2017_improved.zip", dataset["sha256"])
    csv_dir = raw_dir / "cicids2017"
    extract_csvs(zip_path, csv_dir)

    summary = {}
    for day in dataset["days"]:
        print(f"Limpiando {day}…")
        df, stats = load_raw_day(csv_dir / f"{day}.csv", day)
        df.to_parquet(processed_dir / f"{day}.parquet", index=False)
        stats["start_utc"] = df["timestamp"].min().isoformat()
        stats["end_utc"] = df["timestamp"].max().isoformat()
        stats["flows_per_family"] = _counts(df["family"])
        stats["flows_per_label"] = _counts(df["label"])
        summary[day] = stats

    out = project_path(config, "reports") / "data" / "summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Listo: {processed_dir} y {out}")


def _counts(column) -> dict[str, int]:
    counts = column.value_counts()
    return {str(k): int(v) for k, v in counts.items() if v > 0}


if __name__ == "__main__":
    main()
