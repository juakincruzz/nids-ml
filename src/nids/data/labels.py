"""Unificación de etiquetas y agrupación en familias de ataque.

Las etiquetas canónicas son las de la versión corregida (Engelen et al., 2021). La normalización
también acepta las variantes del CIC-IDS2017 original («Web Attack � Brute Force», «PortScan»,
«Bot»…), por si algún día se cargan esos CSV.

Flujos «- Attempted»: son flujos que formaban parte de un ataque pero no llevan nada malicioso.
Los autores piden no tratarlos nunca como una clase aparte y, en caso de duda, reetiquetarlos
como benignos. Eso se hace aquí; la etiqueta original se conserva en `label_raw`.
"""

import re

BENIGN = "BENIGN"

# Clave normalizada -> etiqueta canónica.
_CANONICAL = {
    "benign": BENIGN,
    "ftp patator": "FTP-Patator",
    "ssh patator": "SSH-Patator",
    "dos hulk": "DoS Hulk",
    "dos goldeneye": "DoS GoldenEye",
    "dos slowloris": "DoS Slowloris",
    "dos slowhttptest": "DoS Slowhttptest",
    "ddos": "DDoS",
    "heartbleed": "Heartbleed",
    "web attack brute force": "Web Attack - Brute Force",
    "web attack xss": "Web Attack - XSS",
    "web attack sql injection": "Web Attack - SQL Injection",
    "infiltration": "Infiltration",
    "infiltration portscan": "Infiltration - Portscan",
    "portscan": "Portscan",
    "port scan": "Portscan",
    "botnet": "Botnet",
    "bot": "Botnet",
}

# Etiqueta canónica -> familia. Las familias se definen por el comportamiento en la red, que es
# lo que ve el modelo:
# - «Infiltration - Portscan» es el escaneo que lanza la máquina infectada: va a «scan». Si
#   fuera a «infiltration», al dejar fuera la familia «scan» el modelo seguiría viendo escaneos.
# - Heartbleed no encaja en ninguna de las seis familias y tiene muy pocos flujos: va aparte.
FAMILY_OF = {
    BENIGN: "benign",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS Slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "DDoS": "dos",
    "Heartbleed": "heartbleed",
    "Web Attack - Brute Force": "web",
    "Web Attack - XSS": "web",
    "Web Attack - SQL Injection": "web",
    "Infiltration": "infiltration",
    "Infiltration - Portscan": "scan",
    "Portscan": "scan",
    "Botnet": "botnet",
}

ATTACK_FAMILIES = ("dos", "brute_force", "scan", "web", "botnet", "infiltration", "heartbleed")


def _key(label: str) -> str:
    """'Web Attack � Brute Force' -> 'web attack brute force'."""
    return re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()


def parse_label(raw: str) -> tuple[str, bool]:
    """Devuelve (etiqueta canónica, si es un flujo «Attempted»).

    Lanza ValueError ante una etiqueta desconocida: es mejor parar que tomarla por benigna.
    """
    key = _key(raw)
    attempted = key.endswith(" attempted")
    if attempted:
        key = key.removesuffix(" attempted")
    if key not in _CANONICAL:
        raise ValueError(f"Etiqueta desconocida: {raw!r}")
    return _CANONICAL[key], attempted
