"""Descarga reanudable de CIC-IDS2017 (versión corregida) con barra de progreso.

Se descarga a `<destino>.part`. Si se corta, la siguiente ejecución pide al servidor solo los
bytes que faltan (cabecera HTTP `Range`). Al terminar se comprueba el SHA-256 y se renombra.
"""

import hashlib
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from tqdm import tqdm

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path, expected_sha256: str | None = None) -> Path:
    """Descarga `url` en `dest` reanudando si ya hay una parte. Devuelve la ruta final."""
    if dest.exists():
        _check_sha256(dest, expected_sha256)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    already = part.stat().st_size if part.exists() else 0

    request = urllib.request.Request(url, headers={"Range": f"bytes={already}-"})
    try:
        response = urllib.request.urlopen(request, timeout=60)
    except urllib.error.HTTPError as error:
        if error.code != 416:  # 416: la parte ya está completa, no queda nada por pedir
            raise
        _check_sha256(part, expected_sha256)
        part.rename(dest)
        return dest

    with response:
        if already and response.status != 206:
            # El servidor ignora Range: hay que empezar de cero.
            already = 0
        total = already + int(response.headers.get("Content-Length", 0))
        mode = "ab" if already else "wb"
        with (
            open(part, mode) as f,
            tqdm(total=total, initial=already, unit="B", unit_scale=True, desc=dest.name) as bar,
        ):
            while chunk := response.read(CHUNK_SIZE):
                f.write(chunk)
                bar.update(len(chunk))

    _check_sha256(part, expected_sha256)
    part.rename(dest)
    return dest


def _check_sha256(path: Path, expected: str | None) -> None:
    if expected is None:
        print(f"Aviso: no hay checksum en la configuración. SHA-256 de {path.name}: ")
        print(f"  {sha256_of(path)}")
        return
    actual = sha256_of(path)
    if actual != expected:
        raise ValueError(
            f"SHA-256 incorrecto en {path}: {actual} (se esperaba {expected}). "
            "Borra el fichero y vuelve a descargarlo."
        )


def extract_csvs(zip_path: Path, out_dir: Path) -> list[Path]:
    """Extrae los CSV del ZIP en `out_dir` (planos, sin subcarpetas). Omite los ya extraídos."""
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = Path(info.filename).name
            if not name.lower().endswith(".csv"):
                continue
            target = out_dir / name
            if not target.exists() or target.stat().st_size != info.file_size:
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            extracted.append(target)
    return sorted(extracted)
