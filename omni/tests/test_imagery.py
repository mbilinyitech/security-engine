import http.server
import threading

import pytest

from omnishield import imagery
from omnishield.knowledge import KnowledgeStore
from omnishield.render import chart
from omnishield.vision import decode_png

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Picture one</title><description>look at http://127.0.0.1:PORT/a.png now</description></item>
</channel></rss>"""


@pytest.fixture
def image_server(tmp_path):
    chart([1, 3, 2], title="A").save_png(tmp_path / "a.png")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/feed.xml":
                body = RSS.replace(b"PORT", str(self.server.server_address[1]).encode())
                kind = "application/rss+xml"
            elif self.path == "/robots.txt":
                body, kind = b"", "text/plain"
            else:
                path = tmp_path / self.path.lstrip("/")
                body = path.read_bytes() if path.is_file() else b""
                kind = "image/png"
            self.send_response(200 if body or self.path == "/robots.txt" else 404)
            self.send_header("Content-Type", kind)
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


def test_perceptual_hash_matches_itself_and_separates_images(tmp_path):
    chart([1, 3, 2], title="A").save_png(tmp_path / "a.png")
    chart([3, 1, 2], title="B").save_png(tmp_path / "b.png")
    first = decode_png((tmp_path / "a.png").read_bytes())
    second = decode_png((tmp_path / "b.png").read_bytes())
    digest_a = imagery.perceptual_hash(first["rows"])
    digest_b = imagery.perceptual_hash(second["rows"])
    assert imagery.hamming(digest_a["bits"], digest_a["bits"]) == 0
    assert imagery.hamming(digest_a["bits"], digest_b["bits"]) > 0
    assert len(digest_a["hash"]) == 16
    with pytest.raises(imagery.ImageryError):
        imagery.perceptual_hash([[1, 2], [3, 4]])


def test_image_stats_and_contact_sheet(tmp_path, image_server):
    fetched = imagery.fetch_image(f"{image_server}/a.png", allow_private=True)
    stats = imagery.image_stats(fetched["rows"])
    assert stats["width"] == fetched["width"]
    assert 0 <= stats["saturation"] <= 1
    assert stats["unique_blocks"] >= 2
    sheet = imagery.contact_sheet([{**fetched, "hash": "abc123"}])
    assert sheet.width > 0 and sheet.png().startswith(b"\x89PNG")
    with pytest.raises(imagery.ImageryError):
        imagery.contact_sheet([])


def test_daily_discovers_learns_and_skips_repeats(tmp_path, image_server):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    result = imagery.daily(
        [f"{image_server}/feed.xml"],
        store,
        out_dir=tmp_path / "out",
        seen_path=tmp_path / "seen.json",
        allow_private=True,
    )
    assert result["discovered"] == 1
    assert result["learned"] == 1
    assert result["contact_sheet"] and (tmp_path / "out" / "contact-sheet.png").is_file()
    assert len(store.items) == 1
    again = imagery.daily(
        [f"{image_server}/feed.xml"],
        store,
        out_dir=tmp_path / "out",
        seen_path=tmp_path / "seen.json",
        allow_private=True,
    )
    assert again["learned"] == 0
    assert "already seen" in again["skipped"][0]["reason"]


def test_discovery_needs_a_working_feed(tmp_path):
    from omnishield.ingest import IngestError

    with pytest.raises((imagery.ImageryError, IngestError, OSError)):
        imagery.discover_images("http://127.0.0.1:1/missing.xml", allow_private=True)
