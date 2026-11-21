import hashlib
import os
import time

import pytest

from omnishield.inspect import (
    InspectError,
    process,
    processes,
    read_file,
    read_many,
    snapshot,
    tree,
)


def test_read_file_reports_hash_size_and_preview(tmp_path):
    target = tmp_path / "note.txt"
    payload = "hello inspect\nsecond line\n"
    target.write_text(payload, encoding="utf-8")
    document = read_file(target)
    assert document["size_bytes"] == len(payload.encode())
    assert document["sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert document["binary"] is False
    assert document["preview"] == payload
    assert document["truncated"] is False
    assert document["elapsed_ms"] >= 0


def test_binary_files_are_detected_and_hexed(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00\x01\x02\xff" * 8)
    document = read_file(target)
    assert document["binary"] is True
    assert document["preview_hex"].startswith("000102ff")
    assert document["lines"] is None


def test_reads_are_capped_and_errors_are_clear(tmp_path):
    target = tmp_path / "big.txt"
    target.write_text("x" * 100, encoding="utf-8")
    document = read_file(target, max_bytes=10)
    assert document["bytes_read"] == 10
    assert document["truncated"] is True
    with pytest.raises(InspectError, match="does not exist"):
        read_file(tmp_path / "missing")
    with pytest.raises(InspectError, match="directory"):
        read_file(tmp_path)
    with pytest.raises(InspectError):
        read_file(target, max_bytes=-1)


def test_read_many_collects_failures(tmp_path):
    good = tmp_path / "a.txt"
    good.write_text("a", encoding="utf-8")
    result = read_many([good, tmp_path / "missing"])
    assert result["count"] == 1
    assert result["total_bytes"] == 1
    assert result["failures"][0]["path"].endswith("missing")
    assert result["elapsed_ms"] >= 0


def test_processes_lists_everything_in_milliseconds():
    started = time.perf_counter()
    listing = processes()
    wall = (time.perf_counter() - started) * 1000
    assert listing["available"] is True
    assert listing["count"] >= 1
    assert wall < 1000
    assert listing["elapsed_ms"] < 1000
    pids = [item["pid"] for item in listing["processes"]]
    assert os.getpid() in pids
    record = next(item for item in listing["processes"] if item["pid"] == os.getpid())
    assert record["threads"] >= 1
    assert record["rss_bytes"] > 0
    assert record["state"] in "RSDZTtWXxKIP"
    assert processes(limit=1)["count"] == 1


def test_single_process_matches_the_listing():
    mine = process(os.getpid())
    assert mine["pid"] == os.getpid()
    assert mine["threads"] >= 1
    assert isinstance(mine["argv"], list)
    with pytest.raises(InspectError):
        process(999_999_999)


def test_snapshot_reports_real_resources():
    document = snapshot()
    assert document["available"] is True
    assert document["hostname"]
    assert len(document["loadavg"]) == 3
    assert document["memory"]["total_kb"] > 0
    assert 0 <= document["memory"]["used_pct"] <= 100
    assert document["disk"]["total_bytes"] > 0
    assert document["process_count"] >= 1
    assert document["elapsed_ms"] < 2000


def test_tree_walks_nested_directories_with_a_limit(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()
    (tmp_path / "a" / "b" / "c.txt").write_text("c", encoding="utf-8")
    (tmp_path / "top.txt").write_text("t", encoding="utf-8")
    document = tree(tmp_path, depth=3, limit=50)
    paths = {entry["path"] for entry in document["entries"]}
    assert "top.txt" in paths
    assert os.path.join("a", "b", "c.txt") in paths
    assert document["truncated"] is False
    limited = tree(tmp_path, depth=1, limit=1)
    assert limited["count"] == 1
    assert limited["truncated"] is True
    with pytest.raises(InspectError):
        tree(tmp_path / "missing")
