"""Descarga reanudable contra un servidor HTTP local (no sale a Internet)."""

import hashlib
import http.server
import threading
import zipfile

import pytest

from nids.data.download import download, extract_csvs

PAYLOAD = bytes(range(256)) * 400  # ~100 KB


class _RangeHandler(http.server.BaseHTTPRequestHandler):
    """Sirve PAYLOAD respetando la cabecera Range y apunta qué rangos se piden."""

    requested_ranges: list[str | None] = []

    def do_GET(self):
        range_header = self.headers.get("Range")
        self.requested_ranges.append(range_header)
        start = int(range_header.removeprefix("bytes=").rstrip("-")) if range_header else 0
        body = PAYLOAD[start:]
        self.send_response(206 if start else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server_url():
    _RangeHandler.requested_ranges = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RangeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/data.zip"
    server.shutdown()


SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


def test_descarga_completa(tmp_path, server_url):
    dest = download(server_url, tmp_path / "data.zip", SHA256)
    assert dest.read_bytes() == PAYLOAD
    assert not (tmp_path / "data.zip.part").exists()


def test_reanuda_desde_la_parte_ya_descargada(tmp_path, server_url):
    (tmp_path / "data.zip.part").write_bytes(PAYLOAD[:30_000])
    dest = download(server_url, tmp_path / "data.zip", SHA256)
    assert dest.read_bytes() == PAYLOAD
    assert _RangeHandler.requested_ranges == ["bytes=30000-"]


def test_checksum_incorrecto_falla(tmp_path, server_url):
    with pytest.raises(ValueError, match="SHA-256"):
        download(server_url, tmp_path / "data.zip", "0" * 64)
    assert not (tmp_path / "data.zip").exists()


def test_extrae_solo_los_csv(tmp_path):
    zip_path = tmp_path / "x.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("carpeta/monday.csv", "a,b\n1,2\n")
        zf.writestr("LEEME.txt", "hola")
    extracted = extract_csvs(zip_path, tmp_path / "out")
    assert [p.name for p in extracted] == ["monday.csv"]
    assert (tmp_path / "out" / "monday.csv").read_text() == "a,b\n1,2\n"
