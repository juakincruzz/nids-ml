"""UNSW-NB15 para el protocolo «otra red»: descarga y alineación con las variables de CIC-IDS2017.

UNSW-NB15 es otra red (UNSW Canberra, 2015), con otras herramientas de ataque y otro extractor
de flujos (Argus y Bro en vez de CICFlowMeter). Solo una parte de sus 49 variables significa lo
mismo que alguna de las 83 de CIC-IDS2017; esas se traducen a nombres y unidades de CIC (ver
`align`) y el resto se descarta.
"""

import http.cookiejar
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pandas as pd

from nids.config import load_config, project_path
from nids.data.clean import clean_values
from nids.data.download import download
from nids.evaluation.report import write_json


def raw_dir(config: dict) -> Path:
    return project_path(config, "raw_data") / "unsw_nb15"


def sharepoint_opener(share_url: str) -> urllib.request.OpenerDirector:
    """Sesión con la cookie de invitado que da el enlace compartido (sin ella, 403)."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    with opener.open(share_url, timeout=60) as response:
        response.read()
    return opener


def file_url(site: str, folder: str, name: str) -> str:
    path = quote(f"{folder}/{name}", safe="/")
    return f"{site}/_api/web/GetFileByServerRelativeUrl('{path}')/$value"


def download_unsw(config: dict) -> list[Path]:
    """Descarga los CSV que falten (los completos no se vuelven a pedir)."""
    cfg = config["dataset"]["unsw_nb15"]
    opener = sharepoint_opener(cfg["share_url"])
    paths = []
    for name, sha256 in cfg["files"].items():
        url = file_url(cfg["site"], cfg["folder"], name)
        paths.append(download(url, raw_dir(config) / name, sha256, opener=opener))
    return paths


# --- Alineación con CIC-IDS2017 ------------------------------------------------------------

# Columnas de UNSW-NB15 que hacen falta (los CSV no traen cabecera; los nombres están en
# NUSW-NB15_features.csv).
RAW_COLUMNS = [
    "dsport",
    "proto",
    "dur",
    "Spkts",
    "Dpkts",
    "Sintpkt",
    "Dintpkt",
    "Stime",
    "attack_cat",
    "Label",
]

# Variables que significan lo mismo en los dos extractores, ya con nombre y unidades de CIC.
# Se excluyen a propósito:
# - los bytes y tamaños de paquete: Argus cuenta las cabeceras y CICFlowMeter solo la carga
#   útil, así que tendrían un desfase sistemático (el modelo fallaría por la medida, no por la
#   red);
# - la ventana TCP: el `swin` de Argus nunca pasa de 255, no es la ventana en bytes de CIC.
COMMON_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
]

# CICFlowMeter solo produce flujos TCP y UDP (más algún ICMP suelto); en UNSW-NB15 hay ARP,
# OSPF y otros 130 protocolos que no tienen equivalente. Se evalúan solo TCP y UDP.
PROTOCOLS = {"tcp": 6, "udp": 17}

# Una sesión de captura nueva cuando hay un hueco de más de 6 horas sin flujos.
SESSION_GAP_SECONDS = 6 * 3600


def parse_port(values: pd.Series) -> pd.Series:
    """Puertos: casi todos decimales; unos pocos vienen en hexadecimal («0xcc09») o como «-»."""
    text = values.astype(str).str.strip()
    port = pd.to_numeric(text, errors="coerce")
    is_hex = text.str.startswith("0x")
    port[is_hex] = text[is_hex].map(lambda h: int(h, 16))
    return port


def read_raw(paths: list[Path], features_csv: Path) -> pd.DataFrame:
    names = pd.read_csv(features_csv, encoding="latin1")["Name"].str.strip().tolist()
    frames = [
        pd.read_csv(
            path,
            header=None,
            names=names,
            usecols=RAW_COLUMNS,
            dtype={"dsport": str, "attack_cat": str, "proto": str},
            low_memory=False,
        )
        for path in paths
    ]
    return pd.concat(frames, ignore_index=True)


def align(raw: pd.DataFrame, tz: str) -> tuple[pd.DataFrame, dict]:
    """Traduce UNSW-NB15 a las variables comunes con nombres y unidades de CIC-IDS2017."""
    proto = raw["proto"].str.strip().str.lower()
    kept = proto.isin(PROTOCOLS)
    category = raw["attack_cat"].fillna("").str.strip()
    stats = {
        "rows_raw": len(raw),
        "rows_not_tcp_udp_dropped": int((~kept).sum()),
        "attacks_not_tcp_udp_dropped": int((raw["Label"].astype(bool) & ~kept).sum()),
    }
    raw, proto, category = raw[kept], proto[kept], category[kept]

    dur = raw["dur"].astype("float64")
    fwd, bwd = raw["Spkts"].astype("float64"), raw["Dpkts"].astype("float64")
    df = pd.DataFrame(
        {
            "Dst Port": parse_port(raw["dsport"]),
            "Protocol": proto.map(PROTOCOLS),
            "Flow Duration": dur * 1e6,  # s -> µs
            "Total Fwd Packet": fwd,
            "Total Bwd packets": bwd,
            # Con duración 0 salen infinitos, como en CIC; clean_values los pasa a NaN.
            "Flow Packets/s": (fwd + bwd) / dur,
            "Fwd Packets/s": fwd / dur,
            "Bwd Packets/s": bwd / dur,
            "Fwd IAT Mean": raw["Sintpkt"].astype("float64") * 1e3,  # ms -> µs
            "Bwd IAT Mean": raw["Dintpkt"].astype("float64") * 1e3,
        }
    )

    # Categorías: «Backdoors» y «Backdoor» son la misma.
    category = category.replace({"Backdoors": "Backdoor"})
    df["is_attack"] = raw["Label"].astype(bool).to_numpy()
    df["label"] = category.where(df["is_attack"], "BENIGN").to_numpy()
    df["family"] = df["label"].str.lower()  # «benign», «generic», «exploits»…
    df["timestamp"] = pd.to_datetime(raw["Stime"], unit="s", utc=True)

    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    gap = df["timestamp"].diff().dt.total_seconds().fillna(0) > SESSION_GAP_SECONDS
    session_start = df["timestamp"].where(gap | (df.index == 0)).ffill()
    df["day"] = session_start.dt.tz_convert(tz).dt.strftime("unsw_%Y-%m-%d")
    stats["sessions"] = df["day"].value_counts().sort_index().to_dict()
    return df, stats


def processed_path(config: dict) -> Path:
    return project_path(config, "processed_data") / "unsw_nb15.parquet"


def main() -> None:
    """`make data-unsw`: descarga, alinea y guarda data/processed/unsw_nb15.parquet."""
    config = load_config()
    paths = download_unsw(config)
    features_csv, csvs = paths[0], paths[1:]
    df, stats = align(read_raw(csvs, features_csv), config["dataset"]["unsw_nb15"]["timezone"])
    df, value_stats = clean_values(df)
    stats |= value_stats | {
        "rows": len(df),
        "flows_per_family": {k: int(v) for k, v in df["family"].value_counts().items()},
    }
    out = processed_path(config)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)

    summary = project_path(config, "reports") / "data" / "unsw_summary.json"
    write_json(summary, stats)
    print(f"Listo: {len(df):,} flujos TCP/UDP en {out} y resumen en {summary}")


if __name__ == "__main__":
    main()
