"""Traducción de las variables de CICFlowMeter a lenguaje claro.

Cada variable tiene: nombre legible, unidad y dos frases, una para cuando el valor del flujo está
por encima de lo normal y otra para cuando está por debajo. «Lo normal» es la mediana del
tráfico normal de train.

Unidades de CICFlowMeter: tiempos en microsegundos, tamaños en bytes, tasas por segundo.
"""

# (nombre, unidad, frase si es más alto de lo normal, frase si es más bajo)
FEATURES: dict[str, tuple[str, str, str, str]] = {
    # --- Identidad del servicio ---
    "Dst Port": ("puerto de destino", "port", "", ""),
    "Protocol": ("protocolo", "proto", "", ""),
    # --- Duración ---
    "Flow Duration": (
        "duración del flujo",
        "us",
        "la conexión dura mucho",
        "la conexión es muy corta",
    ),
    "Total TCP Flow Time": (
        "duración de la conexión TCP",
        "us",
        "la conexión TCP dura mucho",
        "la conexión TCP es muy corta",
    ),
    # --- Volumen ---
    "Total Fwd Packet": (
        "paquetes enviados",
        "pkt",
        "el origen envía muchos paquetes",
        "el origen envía muy pocos paquetes",
    ),
    "Total Bwd packets": (
        "paquetes de respuesta",
        "pkt",
        "el destino responde con muchos paquetes",
        "el destino apenas responde",
    ),
    "Total Length of Fwd Packet": (
        "bytes enviados",
        "B",
        "el origen envía muchos datos",
        "el origen apenas envía datos",
    ),
    "Total Length of Bwd Packet": (
        "bytes de respuesta",
        "B",
        "el destino devuelve muchos datos",
        "el destino apenas devuelve datos",
    ),
    "Subflow Fwd Packets": (
        "paquetes enviados por subflujo",
        "pkt",
        "envía muchos paquetes seguidos",
        "envía muy pocos paquetes seguidos",
    ),
    "Subflow Bwd Packets": (
        "paquetes de respuesta por subflujo",
        "pkt",
        "recibe muchos paquetes seguidos",
        "recibe muy pocos paquetes seguidos",
    ),
    "Subflow Fwd Bytes": (
        "bytes enviados por subflujo",
        "B",
        "envía muchos datos de golpe",
        "envía muy pocos datos de golpe",
    ),
    "Subflow Bwd Bytes": (
        "bytes de respuesta por subflujo",
        "B",
        "recibe muchos datos de golpe",
        "recibe muy pocos datos de golpe",
    ),
    "Fwd Act Data Pkts": (
        "paquetes enviados con datos",
        "pkt",
        "envía muchos paquetes con contenido",
        "casi no envía paquetes con contenido",
    ),
    "Down/Up Ratio": (
        "proporción recibido/enviado",
        "ratio",
        "recibe más de lo que envía",
        "envía más de lo que recibe",
    ),
    # --- Ritmo ---
    "Flow Bytes/s": (
        "bytes por segundo",
        "B/s",
        "mueve datos muy deprisa",
        "mueve datos muy despacio",
    ),
    "Flow Packets/s": (
        "paquetes por segundo",
        "pkt/s",
        "envía paquetes muy deprisa",
        "envía paquetes muy despacio",
    ),
    "Fwd Packets/s": (
        "paquetes enviados por segundo",
        "pkt/s",
        "el origen envía paquetes muy deprisa",
        "el origen envía paquetes muy despacio",
    ),
    "Bwd Packets/s": (
        "respuestas por segundo",
        "pkt/s",
        "el destino responde muy deprisa",
        "el destino responde muy despacio",
    ),
    # --- Tamaño de los paquetes enviados ---
    "Fwd Packet Length Max": (
        "paquete enviado más grande",
        "B",
        "envía algún paquete muy grande",
        "todos los paquetes que envía son pequeños",
    ),
    "Fwd Packet Length Min": (
        "paquete enviado más pequeño",
        "B",
        "hasta sus paquetes más pequeños son grandes",
        "envía paquetes vacíos o diminutos",
    ),
    "Fwd Packet Length Mean": (
        "tamaño medio de lo enviado",
        "B",
        "envía paquetes grandes",
        "envía paquetes pequeños",
    ),
    "Fwd Packet Length Std": (
        "variación del tamaño de lo enviado",
        "B",
        "lo que envía varía mucho de tamaño",
        "todo lo que envía tiene casi el mismo tamaño",
    ),
    "Fwd Segment Size Avg": (
        "tamaño medio de segmento enviado",
        "B",
        "envía segmentos grandes",
        "envía segmentos pequeños",
    ),
    "Fwd Seg Size Min": (
        "cabecera mínima enviada",
        "B",
        "sus cabeceras son más largas de lo habitual",
        "sus cabeceras son más cortas de lo habitual",
    ),
    "Fwd Header Length": (
        "bytes de cabecera enviados",
        "B",
        "envía muchas cabeceras",
        "envía pocas cabeceras",
    ),
    # --- Tamaño de las respuestas ---
    "Bwd Packet Length Max": (
        "respuesta más grande",
        "B",
        "recibe alguna respuesta muy grande",
        "todas las respuestas son pequeñas",
    ),
    "Bwd Packet Length Min": (
        "respuesta más pequeña",
        "B",
        "hasta las respuestas más pequeñas son grandes",
        "recibe respuestas vacías o diminutas",
    ),
    "Bwd Packet Length Mean": (
        "tamaño medio de las respuestas",
        "B",
        "recibe respuestas grandes",
        "recibe respuestas pequeñas",
    ),
    "Bwd Packet Length Std": (
        "variación del tamaño de las respuestas",
        "B",
        "las respuestas varían mucho de tamaño",
        "todas las respuestas tienen casi el mismo tamaño",
    ),
    "Bwd Segment Size Avg": (
        "tamaño medio de segmento recibido",
        "B",
        "recibe segmentos grandes",
        "recibe segmentos pequeños",
    ),
    "Bwd Header Length": (
        "bytes de cabecera recibidos",
        "B",
        "recibe muchas cabeceras",
        "recibe pocas cabeceras",
    ),
    # --- Tamaño de todos los paquetes ---
    "Packet Length Min": (
        "paquete más pequeño",
        "B",
        "no hay ningún paquete pequeño",
        "hay paquetes vacíos o diminutos",
    ),
    "Packet Length Max": (
        "paquete más grande",
        "B",
        "hay algún paquete muy grande",
        "todos los paquetes son pequeños",
    ),
    "Packet Length Mean": (
        "tamaño medio de paquete",
        "B",
        "los paquetes son grandes",
        "los paquetes son pequeños",
    ),
    "Packet Length Std": (
        "variación del tamaño de paquete",
        "B",
        "los paquetes varían mucho de tamaño",
        "todos los paquetes tienen casi el mismo tamaño",
    ),
    "Packet Length Variance": (
        "varianza del tamaño de paquete",
        "B²",
        "los paquetes varían mucho de tamaño",
        "todos los paquetes tienen casi el mismo tamaño",
    ),
    "Average Packet Size": (
        "tamaño medio de paquete",
        "B",
        "los paquetes son grandes",
        "los paquetes son pequeños",
    ),
    # --- Tiempo entre paquetes (todo el flujo) ---
    "Flow IAT Mean": (
        "tiempo medio entre paquetes",
        "us",
        "pasa mucho tiempo entre paquetes",
        "los paquetes van casi seguidos",
    ),
    "Flow IAT Std": (
        "irregularidad del ritmo",
        "us",
        "el ritmo de paquetes es muy irregular",
        "el ritmo de paquetes es muy regular",
    ),
    "Flow IAT Max": (
        "pausa más larga entre paquetes",
        "us",
        "hay pausas largas entre paquetes",
        "no hay pausas entre paquetes",
    ),
    "Flow IAT Min": (
        "pausa más corta entre paquetes",
        "us",
        "ni los paquetes más seguidos van juntos",
        "hay paquetes prácticamente simultáneos",
    ),
    # --- Tiempo entre paquetes enviados ---
    "Fwd IAT Total": (
        "tiempo total entre envíos",
        "us",
        "los envíos se reparten en mucho tiempo",
        "todos los envíos se concentran en un instante",
    ),
    "Fwd IAT Mean": (
        "tiempo medio entre envíos",
        "us",
        "envía con mucha calma",
        "envía casi sin pausa",
    ),
    "Fwd IAT Std": (
        "irregularidad de los envíos",
        "us",
        "envía a un ritmo muy irregular",
        "envía a un ritmo muy regular",
    ),
    "Fwd IAT Max": (
        "pausa más larga entre envíos",
        "us",
        "hace pausas largas entre envíos",
        "no hace pausas entre envíos",
    ),
    "Fwd IAT Min": (
        "pausa más corta entre envíos",
        "us",
        "nunca envía dos paquetes seguidos",
        "envía paquetes prácticamente a la vez",
    ),
    # --- Tiempo entre respuestas ---
    "Bwd IAT Total": (
        "tiempo total entre respuestas",
        "us",
        "las respuestas se reparten en mucho tiempo",
        "todas las respuestas llegan en un instante",
    ),
    "Bwd IAT Mean": (
        "tiempo medio entre respuestas",
        "us",
        "el destino responde con mucha calma",
        "el destino responde casi sin pausa",
    ),
    "Bwd IAT Std": (
        "irregularidad de las respuestas",
        "us",
        "el destino responde a un ritmo muy irregular",
        "el destino responde a un ritmo muy regular",
    ),
    "Bwd IAT Max": (
        "pausa más larga entre respuestas",
        "us",
        "hay pausas largas entre respuestas",
        "no hay pausas entre respuestas",
    ),
    "Bwd IAT Min": (
        "pausa más corta entre respuestas",
        "us",
        "las respuestas nunca van seguidas",
        "hay respuestas prácticamente simultáneas",
    ),
    # --- Actividad y silencios ---
    "Active Mean": (
        "tiempo activo medio",
        "us",
        "está activa mucho rato seguido",
        "solo tiene ráfagas de actividad muy cortas",
    ),
    "Active Std": (
        "variación del tiempo activo",
        "us",
        "sus ráfagas de actividad son muy desiguales",
        "sus ráfagas de actividad son muy parecidas",
    ),
    "Active Max": (
        "ráfaga de actividad más larga",
        "us",
        "tiene alguna ráfaga de actividad muy larga",
        "todas sus ráfagas de actividad son cortas",
    ),
    "Active Min": (
        "ráfaga de actividad más corta",
        "us",
        "incluso su ráfaga más corta es larga",
        "tiene ráfagas de actividad muy cortas",
    ),
    "Idle Mean": ("silencio medio", "us", "tiene largos silencios", "apenas tiene silencios"),
    "Idle Std": (
        "variación de los silencios",
        "us",
        "sus silencios son muy desiguales",
        "sus silencios son muy parecidos",
    ),
    "Idle Max": (
        "silencio más largo",
        "us",
        "tiene algún silencio muy largo",
        "no tiene silencios largos",
    ),
    "Idle Min": (
        "silencio más corto",
        "us",
        "incluso su silencio más corto es largo",
        "tiene silencios muy cortos",
    ),
    # --- Banderas TCP ---
    "FIN Flag Count": (
        "paquetes FIN",
        "count",
        "cierra la conexión varias veces",
        "no cierra la conexión de forma ordenada",
    ),
    "SYN Flag Count": (
        "paquetes SYN",
        "count",
        "intenta abrir la conexión repetidamente",
        "no abre la conexión con SYN",
    ),
    "RST Flag Count": (
        "paquetes RST",
        "count",
        "la conexión se corta de golpe",
        "la conexión no se corta de golpe",
    ),
    "PSH Flag Count": (
        "paquetes PSH",
        "count",
        "fuerza el envío inmediato de datos a menudo",
        "no fuerza el envío inmediato de datos",
    ),
    "ACK Flag Count": (
        "paquetes ACK",
        "count",
        "hay muchos acuses de recibo",
        "casi no hay acuses de recibo",
    ),
    "URG Flag Count": (
        "paquetes URG",
        "count",
        "marca datos como urgentes",
        "no marca datos como urgentes",
    ),
    "CWR Flag Count": (
        "paquetes CWR",
        "count",
        "reduce su ritmo por congestión",
        "no reacciona a congestión",
    ),
    "ECE Flag Count": ("paquetes ECE", "count", "avisa de congestión", "no avisa de congestión"),
    "Fwd PSH Flags": (
        "envíos con PSH",
        "count",
        "el origen fuerza el envío inmediato de datos",
        "el origen no fuerza el envío inmediato de datos",
    ),
    "Bwd PSH Flags": (
        "respuestas con PSH",
        "count",
        "el destino fuerza el envío inmediato de datos",
        "el destino no fuerza el envío inmediato de datos",
    ),
    "Fwd URG Flags": (
        "envíos con URG",
        "count",
        "el origen marca datos como urgentes",
        "el origen no marca datos como urgentes",
    ),
    "Bwd URG Flags": (
        "respuestas con URG",
        "count",
        "el destino marca datos como urgentes",
        "el destino no marca datos como urgentes",
    ),
    "Fwd RST Flags": (
        "envíos con RST",
        "count",
        "el origen corta la conexión de golpe",
        "el origen no corta la conexión de golpe",
    ),
    "Bwd RST Flags": (
        "respuestas con RST",
        "count",
        "el destino corta la conexión de golpe",
        "el destino no corta la conexión de golpe",
    ),
    # --- Ventana TCP inicial (suele delatar la herramienta o el sistema operativo) ---
    "FWD Init Win Bytes": (
        "ventana TCP inicial del origen",
        "B",
        "el origen anuncia una ventana TCP grande",
        "el origen anuncia una ventana TCP pequeña o nula",
    ),
    "Bwd Init Win Bytes": (
        "ventana TCP inicial del destino",
        "B",
        "el destino anuncia una ventana TCP grande",
        "el destino anuncia una ventana TCP pequeña o nula",
    ),
    # --- Envío en bloque (bulk) ---
    "Fwd Bytes/Bulk Avg": (
        "bytes por bloque enviado",
        "B",
        "envía datos en bloques grandes",
        "no envía datos en bloque",
    ),
    "Fwd Packet/Bulk Avg": (
        "paquetes por bloque enviado",
        "pkt",
        "envía bloques de muchos paquetes",
        "no envía datos en bloque",
    ),
    "Fwd Bulk Rate Avg": (
        "ritmo de los bloques enviados",
        "B/s",
        "envía bloques muy deprisa",
        "no envía datos en bloque",
    ),
    "Bwd Bytes/Bulk Avg": (
        "bytes por bloque recibido",
        "B",
        "recibe datos en bloques grandes",
        "no recibe datos en bloque",
    ),
    "Bwd Packet/Bulk Avg": (
        "paquetes por bloque recibido",
        "pkt",
        "recibe bloques de muchos paquetes",
        "no recibe datos en bloque",
    ),
    "Bwd Bulk Rate Avg": (
        "ritmo de los bloques recibidos",
        "B/s",
        "recibe bloques muy deprisa",
        "no recibe datos en bloque",
    ),
    # --- ICMP (-1 = no es ICMP) ---
    "ICMP Code": ("código ICMP", "raw", "", ""),
    "ICMP Type": ("tipo ICMP", "raw", "", ""),
}

_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    444: "SNPP",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP alternativo",
}
_PROTOCOLS = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}


def _number(x: float, decimals: int = 1) -> str:
    """Número a la española: 12 345,6."""
    text = f"{int(x):,}" if float(x).is_integer() else f"{x:,.{decimals}f}"
    return text.replace(",", " ").replace(".", ",")


def format_value(value: float, unit: str) -> str:
    """Valor legible con su unidad (los microsegundos pasan a ms o s, los bytes a kB o MB)."""
    if unit == "port":
        port = int(value)
        return f"{port} ({_SERVICES[port]})" if port in _SERVICES else str(port)
    if unit == "proto":
        return _PROTOCOLS.get(int(value), str(int(value)))
    if unit == "us":
        if abs(value) >= 1e6:
            return f"{_number(value / 1e6)} s"
        if abs(value) >= 1e3:
            return f"{_number(value / 1e3)} ms"
        return f"{_number(value, 0)} µs"
    if unit in ("B", "B/s"):
        suffix = unit[1:]
        for factor, prefix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
            if abs(value) >= factor:
                return f"{_number(value / factor)} {prefix}B{suffix}"
        return f"{_number(value, 0)} B{suffix}"
    if unit == "pkt":
        return f"{_number(value, 0)} paquetes"
    if unit == "pkt/s":
        return f"{_number(value)} paquetes/s"
    if unit == "count":
        return _number(value, 0)
    return _number(value, 2)


def describe(feature: str, value: float, normal: float) -> str:
    """Frase en lenguaje claro sobre una variable de un flujo comparada con lo normal."""
    name, unit, if_high, if_low = FEATURES[feature]
    if unit in ("port", "proto"):
        return name  # el valor ya lo dice todo: «puerto de destino: 22 (SSH)»
    if value > normal and if_high:
        return if_high
    if value < normal and if_low:
        return if_low
    return f"{name} poco habitual"
