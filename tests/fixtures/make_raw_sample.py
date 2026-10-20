"""Genera raw_day_sample.csv: un día sintético con la cabecera real de la versión corregida.

Cada fila está pensada para un caso de la limpieza (ver tests/test_clean.py). Se versiona el CSV
generado; este script solo hace falta si hay que cambiarlo:

    python tests/fixtures/make_raw_sample.py
"""

import csv
from pathlib import Path

HEADER = [
    "id",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd RST Flags",
    "Bwd RST Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWR Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "FWD Init Win Bytes",
    "Bwd Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "ICMP Code",
    "ICMP Type",
    "Total TCP Flow Time",
    "Label",
    "Attempted Category",
]

# (id, timestamp, etiqueta, categoría «attempted», cambios sobre la fila base)
ROWS = [
    (
        1,
        "2017-07-03 12:00:05.000000",
        "BENIGN",
        -1,
        {"Flow Bytes/s": "inf", "Flow Packets/s": "inf"},
    ),
    (2, "2017-07-03 12:00:01.000000", "BENIGN", -1, {"Fwd Header Length": -20}),
    (3, "2017-07-03 12:00:03.000000", "Portscan", -1, {"Dst Port": 22, "Flow Duration": 40}),
    # Repetición exacta de la fila 3 salvo el id: error de exportación, se elimina.
    (4, "2017-07-03 12:00:03.000000", "Portscan", -1, {"Dst Port": 22, "Flow Duration": 40}),
    (5, "2017-07-03 12:00:04.000000", "SSH-Patator - Attempted", 3, {"Dst Port": 22}),
    # Variante de etiqueta del CIC-IDS2017 original (con el carácter de reemplazo).
    (6, "2017-07-03 12:00:06.000000", "Web Attack � Brute Force", -1, {"Dst Port": 80}),
    (7, "2017-07-03 12:00:07.000000", "Infiltration - Portscan", -1, {"Dst Port": 445}),
    (
        8,
        "2017-07-03 12:00:08.000000",
        "BENIGN",
        -1,
        {"Protocol": 1, "ICMP Code": 0, "ICMP Type": 8},
    ),
    (9, "2017-07-03 12:00:02.000000", "DDoS", -1, {"Dst Port": 80, "Flow Duration": 7}),
    # Mismas variables que la fila 1, pero otra hora y otro puerto de origen: se conserva.
    (
        10,
        "2017-07-03 12:00:09.000000",
        "BENIGN",
        -1,
        {"Flow Bytes/s": "inf", "Flow Packets/s": "inf", "Src Port": 50001},
    ),
]


def make_row(row_id, timestamp, label, attempted, changes):
    row = dict.fromkeys(HEADER, 0)
    row |= {
        "id": row_id,
        "Flow ID": f"192.168.10.5-192.168.10.50-{40000 + row_id}-80-6",
        "Src IP": "192.168.10.5",
        "Src Port": 40000 + (row_id if row_id != 4 else 3),
        "Dst IP": "192.168.10.50",
        "Dst Port": 443,
        "Protocol": 6,
        "Timestamp": timestamp,
        "Flow Duration": 1000,
        "Fwd Header Length": 20,
        "ICMP Code": -1,
        "ICMP Type": -1,
        "Label": label,
        "Attempted Category": attempted,
    }
    if row_id == 4:  # misma fila que la 3, también el Flow ID
        row["Flow ID"] = "192.168.10.5-192.168.10.50-40003-80-6"
    return row | changes


if __name__ == "__main__":
    out = Path(__file__).with_name("raw_day_sample.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        for spec in ROWS:
            writer.writerow(make_row(*spec))
    print(f"Escrito {out}")
