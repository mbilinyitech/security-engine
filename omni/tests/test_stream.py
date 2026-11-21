import http.server
import threading

import pytest

from omnishield.stream import (
    StreamError,
    Telemetry,
    chunked_copy,
    disk_benchmark,
    parallel_fetch,
    pipeline,
    resume_download,
    simulate_air,
)


def test_chunked_copy_verifies_and_measures(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(bytes(range(256)) * 128)
    result = chunked_copy(source, tmp_path / "copy.bin", chunk_size=4096)
    assert result["verified"] is True
    assert result["bytes"] == source.stat().st_size
    assert result["chunks"] == 8
    assert result["mb_per_s"] > 0
    assert (tmp_path / "copy.bin").read_bytes() == source.read_bytes()
    with pytest.raises(StreamError):
        chunked_copy(tmp_path / "missing.bin", tmp_path / "x.bin")
    with pytest.raises(StreamError):
        chunked_copy(source, tmp_path / "y.bin", chunk_size=100)


def test_pipeline_counts_and_benchmark_runs(tmp_path):
    lines = ['{"a": 1}', '{"a": 2}', "broken", '{"a": 3}', ""]
    result = pipeline(lines, [lambda item: item if item["a"] > 1 else None])
    assert result["passed"] == 2
    assert result["dropped"] == 2
    assert result["items_per_s"] > 0
    bench = disk_benchmark(1, directory=tmp_path)
    assert bench["write_mb_per_s"] > 0 and bench["read_mb_per_s"] > 0
    with pytest.raises(StreamError):
        disk_benchmark(0)


@pytest.fixture
def file_server(tmp_path):
    payloads = {"a.bin": b"A" * 700, "b.bin": b"B" * 500, "c.bin": b"C" * 300}
    for name, body in payloads.items():
        (tmp_path / name).write_bytes(body)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            name = self.path.lstrip("/")
            body = payloads.get(name)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            start = 0
            header = self.headers.get("Range")
            if header and header.startswith("bytes="):
                start = int(header.split("=")[1].split("-")[0])
                body = body[start:]
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{start + len(body) - 1}/700")
            else:
                self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join()


def test_parallel_fetch_and_resume(file_server, tmp_path):
    base = file_server
    batch = parallel_fetch([f"{base}/a.bin", f"{base}/b.bin", f"{base}/missing.bin"], workers=3, allow_private=True)
    assert batch["ok"] == 2 and batch["failed"] == 1
    assert batch["bytes"] == 1200
    assert batch["mb_per_s"] > 0
    resumed = resume_download(f"{base}/a.bin", tmp_path / "downloads" / "a.bin", chunk_size=200, allow_private=True)
    assert resumed["bytes"] == 700
    assert resumed["rounds"] >= 4
    assert (tmp_path / "downloads" / "a.bin").read_bytes() == b"A" * 700


def test_telemetry_window_alerts_and_reload(tmp_path):
    telemetry = Telemetry(tmp_path / "air.jsonl", window=5)
    for row in simulate_air(3):
        telemetry.ingest(row)
    stats = telemetry.stats()
    assert stats["samples"] == 3
    assert 19 < stats["o2_pct"]["mean"] < 21
    telemetry.ingest({"t": 0, "o2_pct": 20.9, "co2_ppm": 1800, "temp_c": 22.0, "humidity_pct": 45.0})
    alerts = telemetry.alerts()
    assert alerts and alerts[0]["metric"] == "co2_ppm"
    assert alerts[0]["issue"] == "above"
    reloaded = Telemetry(tmp_path / "air.jsonl", window=5)
    assert len(reloaded.samples) == 4
    with pytest.raises(StreamError):
        telemetry.ingest({"o2_pct": 20.9})
    with pytest.raises(StreamError):
        Telemetry(tmp_path / "x.jsonl", window=1)
