import http.server
import threading

import pytest

from omnishield.ingest import (
    IngestError,
    extract_text,
    fetch_url,
    ingest_feed,
    ingest_page,
    parse_feed,
    parse_robots,
    robots_allowed,
)
from omnishield.knowledge import KnowledgeStore

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>First</title><link>http://example.test/1</link>
<description>Lions live in prides and hunt together in the savanna.</description></item>
<item><title>Second</title><link>http://example.test/2</link>
<description>Rust ownership prevents data races without a garbage collector.</description></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Atom one</title><link href="http://example.test/a"/>
<summary>Atoms carry a title, a link and a summary in the feed.</summary></entry>
</feed>"""


class Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}  # noqa: RUF012 - filled by the fixture

    def do_GET(self):
        body, content_type, status = self.routes.get(
            self.path, (b"missing", "text/plain", 404)
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Handler.routes = {
        "/robots.txt": (b"User-agent: *\nDisallow: /private\n", "text/plain", 200),
        "/feed.xml": (RSS, "application/rss+xml", 200),
        "/page.html": (
            (
                b"<html><head><title>Doc</title></head><body><script>bad()</script>"
                b"<p>Hello <b>world</b> from the page.</p></body></html>"
            ),
            "text/html",
            200,
        ),
        "/private/secret": (b"secret", "text/plain", 200),
        "/redirect": (b"", "text/plain", 302),
    }
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    thread.join()


def test_private_addresses_are_refused_by_default(server):
    with pytest.raises(IngestError, match="private or loopback"):
        fetch_url(f"{server}/page.html")
    with pytest.raises(IngestError, match="only http"):
        fetch_url("file:///etc/passwd")


def test_fetch_reads_a_real_local_page(server):
    fetched = fetch_url(f"{server}/page.html", allow_private=True)
    assert fetched["status"] == 200
    assert b"Hello" in fetched["body"]
    assert fetched["elapsed_ms"] >= 0


def test_robots_rules_are_obeyed(server):
    assert robots_allowed(f"{server}/page.html", allow_private=True) is True
    assert robots_allowed(f"{server}/private/secret", allow_private=True) is False
    policy = parse_robots("User-agent: bot\nDisallow: /a\nAllow: /a/b\n")
    assert policy[0]["agents"] == ["bot"]


def test_extract_text_strips_scripts_and_tags():
    text = extract_text("<p>Hello <b>world</b></p><script>evil()</script>")
    assert text == "Hello world"
    assert extract_text(b"<div>a</div><div>b</div>") == "a\nb"


def test_feeds_parse_in_both_formats():
    rss = parse_feed(RSS)
    assert [entry["title"] for entry in rss] == ["First", "Second"]
    assert rss[0]["link"] == "http://example.test/1"
    atom = parse_feed(ATOM)
    assert atom[0]["title"] == "Atom one"
    assert atom[0]["link"] == "http://example.test/a"
    with pytest.raises(IngestError):
        parse_feed(b"<not-xml")


def test_ingest_page_and_feed_write_to_the_store(server, tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    page = ingest_page(f"{server}/page.html", store, allow_private=True, tags=["web"])
    assert page["ingested"] is True
    assert page["created"] is True
    feed = ingest_feed(f"{server}/feed.xml", store, allow_private=True, tags=["news"])
    assert feed["ok"] is True
    assert feed["added"] == 2
    again = ingest_feed(f"{server}/feed.xml", store, allow_private=True, tags=["news"])
    assert again["added"] == 0
    assert again["duplicates"] == 2
    blocked = ingest_page(f"{server}/private/secret", store, allow_private=True)
    assert blocked["ingested"] is False
    assert "robots" in blocked["reason"]
    assert store.stats()["items"] == 3
