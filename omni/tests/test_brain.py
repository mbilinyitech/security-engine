import http.server
import json
import threading

import pytest

from omnishield.brain import (
    BrainError,
    DailyCycle,
    WorkingMemory,
    curiosity,
    intrinsic_reward,
    knowledge_gap_report,
    prediction_error,
    run_forever,
    sleep,
)
from omnishield.knowledge import KnowledgeStore

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Lions</title><link>http://example.test/1</link>
<description>Lions live in prides and hunt together across the savanna.</description></item>
<item><title>Rust</title><link>http://example.test/2</link>
<description>Rust ownership prevents data races without a garbage collector.</description></item>
</channel></rss>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body, status = (RSS, 200) if self.path == "/feed.xml" else (b"missing", 404)
        self.send_response(status)
        self.send_header("Content-Type", "application/rss+xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def feed_server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/feed.xml"
    httpd.shutdown()
    thread.join()


def test_working_memory_evicts_the_weakest():
    memory = WorkingMemory(capacity=3)
    assert memory.add({"task": "a"}, salience=0.9) is None
    assert memory.add({"task": "b"}, salience=0.2) is None
    assert memory.add({"task": "c"}, salience=0.7) is None
    evicted = memory.add({"task": "d"}, salience=0.8)
    assert evicted["task"] == "b"
    assert [item["task"] for item in memory.contents()] == ["a", "d", "c"]
    memory.clear()
    assert memory.contents() == []
    with pytest.raises(BrainError):
        WorkingMemory(capacity=0)


def test_prediction_error_and_intrinsic_reward():
    error = prediction_error({"a": 0.8, "b": 0.2}, {"a": 0.3, "b": 0.2})
    assert error["mean_error"] == 0.25
    assert error["worst"] == "a"
    assert error["surprising"] is True
    reward = intrinsic_reward(0.9, 0.4, 0.7)
    assert reward["reward"] == 0.675
    assert reward["dominant"] == "novelty"
    assert reward["seek"] is True
    with pytest.raises(BrainError):
        intrinsic_reward(1.5, 0.1, 0.1)


def test_curiosity_prefers_unseen_topics(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("lions hunt in prides", source="a", tags=["animals"])
    store.add("more about lions and prides", source="b", tags=["animals"])
    ranked = curiosity(store, topics=["animals", "physics"], limit=2)
    assert ranked[0]["topic"] == "physics"
    assert ranked[0]["items"] == 0
    assert ranked[0]["question"].startswith("nini tunachojua")


def test_daily_cycle_reads_a_real_feed(feed_server, tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    cycle = DailyCycle(store, feeds=[feed_server], allow_private=True, tags=["news"])
    report = cycle.run()
    assert report["added"] == 2
    assert report["failed_feeds"] == []
    assert report["maintenance"]["kept"] == 2
    assert report["stats"]["items"] == 2
    assert report["questions_after"]
    assert report["elapsed_ms"] >= 0
    second = cycle.run()
    assert second["added"] == 0
    assert second["duplicates"] == 2


def test_cycle_survives_a_broken_feed(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    report = DailyCycle(store, feeds=["http://127.0.0.1:1/none"], allow_private=True).run()
    assert report["added"] == 0
    assert report["failed_feeds"] == ["http://127.0.0.1:1/none"]


def test_sleep_and_gap_report(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("alpha beta gamma delta epsilon", source="a", tags=["one"])
    store.add("alpha beta gamma delta epsilon zeta", source="b", tags=["two"])
    result = sleep(store)
    assert result["merged"] == 1
    assert result["kept"] == 1
    report = knowledge_gap_report(store, limit=2)
    assert report["items"] == 1
    assert len(report["rare_terms"]) <= 2


def test_run_forever_writes_a_cycle_log(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("a fact that already exists", source="a")
    cycle = DailyCycle(store)
    log = tmp_path / "cycles.jsonl"
    completed = run_forever(cycle, interval_s=1, log_path=log, cycles=1, sleep_fn=lambda seconds: None)
    assert len(completed) == 1
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["stats"]["items"] == 1
    with pytest.raises(BrainError):
        run_forever(cycle, interval_s=0, log_path=log, cycles=1)
