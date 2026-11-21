"""Fetch pages and feeds politely, then hand the text to the knowledge store.

Politeness is enforced in code, not in a comment: robots.txt is read and obeyed,
private addresses are refused unless explicitly allowed, every read is capped,
and redirects are re-validated instead of followed blindly.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import time
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from .knowledge import KnowledgeStore

USER_AGENT = "OmniShield/1.0 (+knowledge loop; robots.txt respected)"
MAX_REDIRECTS = 3


class IngestError(Exception):
    pass


def _host_is_public(host: str) -> bool:
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise IngestError(f"cannot resolve {host}: {exc}") from exc
    if not addresses:
        raise IngestError(f"{host} resolved to nothing")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            return False
    return True


def _validate(url: str, *, allow_private: bool) -> tuple[str, str, str, int | None]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise IngestError("only http and https are allowed")
    if not parts.hostname:
        raise IngestError("the URL has no host")
    if not allow_private and not _host_is_public(parts.hostname):
        raise IngestError("refusing a private or loopback address; pass allow_private to override")
    return parts.scheme, parts.hostname, parts.path or "/", parts.port


def fetch_url(
    url: str,
    *,
    max_bytes: int = 2_000_000,
    timeout: float = 10.0,
    allow_private: bool = False,
    user_agent: str = USER_AGENT,
) -> dict[str, Any]:
    started = time.perf_counter()
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, path, port = _validate(current, allow_private=allow_private)
        connection_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        connection = connection_class(host, port=port, timeout=timeout)
        try:
            connection.request(
                "GET", path, headers={"User-Agent": user_agent, "Accept": "*/*"}
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location:
                    raise IngestError("a redirect without a Location header")
                current = urljoin(current, location)
                continue
            body = response.read(max_bytes + 1)
            truncated = len(body) > max_bytes
            return {
                "url": current,
                "status": response.status,
                "content_type": response.getheader("Content-Type", ""),
                "body": body[:max_bytes],
                "truncated": truncated,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            }
        finally:
            connection.close()
    raise IngestError("too many redirects")


def parse_robots(text: str) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if current is None or current["rules"]:
                current = {"agents": [], "rules": []}
                groups.append(current)
            current["agents"].append(value.lower())
        elif key in {"allow", "disallow"} and current is not None:
            current["rules"].append({"allow": key == "allow", "path": value})
    return groups


def robots_allowed(
    url: str,
    *,
    policy_text: str | None = None,
    allow_private: bool = False,
    timeout: float = 5.0,
    user_agent: str = USER_AGENT,
) -> bool:
    parts = urlsplit(url)
    if policy_text is None:
        robots_url = urljoin(url, "/robots.txt")
        try:
            fetched = fetch_url(
                robots_url,
                max_bytes=200_000,
                timeout=timeout,
                allow_private=allow_private,
                user_agent=user_agent,
            )
        except (IngestError, OSError):
            return True
        if fetched["status"] != 200:
            return True
        policy_text = fetched["body"].decode("utf-8", "replace")
    groups = parse_robots(policy_text)
    agent = user_agent.split("/")[0].lower()
    chosen = [group for group in groups if "*" in group["agents"] or agent in group["agents"]]
    if not chosen:
        return True
    rules = [rule for group in chosen for rule in group["rules"] if rule["path"]]
    best: dict[str, Any] | None = None
    for rule in rules:
        pattern = re.escape(rule["path"]).replace(r"\*", ".*")
        if pattern.endswith(r"\$"):
            pattern = pattern[:-2] + "$"
        if re.match(pattern, parts.path or "/") and (
            best is None or len(rule["path"]) > len(best["path"])
        ):
            best = rule
    return best is None or best["allow"]


def extract_text(markup: str | bytes) -> str:
    if isinstance(markup, bytes):
        markup = markup.decode("utf-8", "replace")
    text = re.sub(r"(?is)<(script|style|noscript)\b.*?</\1>", " ", markup)
    text = re.sub(r"(?s)<!--.*?-->", " ", text)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = unescape(text)
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(data: bytes | str) -> list[dict[str, Any]]:
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise IngestError(f"the feed is not valid XML: {exc}") from exc
    entries: list[dict[str, Any]] = []
    for element in root.iter():
        if _strip_namespace(element.tag) not in {"item", "entry"}:
            continue
        record: dict[str, Any] = {"title": "", "link": "", "summary": "", "published": ""}
        for child in element:
            name = _strip_namespace(child.tag)
            if name == "title":
                record["title"] = (child.text or "").strip()
            elif name == "link":
                record["link"] = (child.get("href") or child.text or "").strip()
            elif name in {"description", "summary", "content"}:
                record["summary"] = (child.text or "").strip()
            elif name in {"pubdate", "published", "updated"}:
                record["published"] = (child.text or "").strip()
        if record["title"] or record["summary"]:
            entries.append(record)
    if not entries:
        raise IngestError("no items or entries were found in the feed")
    return entries


def _title_of(markup: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", markup)
    return re.sub(r"\s+", " ", unescape(match.group(1))).strip() if match else ""


def ingest_page(
    url: str,
    store: KnowledgeStore,
    *,
    allow_private: bool = False,
    tags: list[str] | tuple[str, ...] = (),
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    if not robots_allowed(url, allow_private=allow_private):
        return {"url": url, "ingested": False, "reason": "robots.txt disallows this path"}
    fetched = fetch_url(url, max_bytes=max_bytes, allow_private=allow_private)
    if fetched["status"] != 200:
        return {"url": url, "ingested": False, "reason": f"HTTP {fetched['status']}"}
    raw = fetched["body"].decode("utf-8", "replace")
    text = extract_text(raw) if "html" in fetched["content_type"].lower() or raw.lstrip().startswith("<") else raw
    if len(text.strip()) < 20:
        return {"url": url, "ingested": False, "reason": "the page had almost no text"}
    written = store.add(text, source=url, title=_title_of(raw), tags=tags)
    return {"url": url, "ingested": True, **written, "chars": len(text), "elapsed_ms": fetched["elapsed_ms"]}


def ingest_feed(
    url: str,
    store: KnowledgeStore,
    *,
    limit: int = 20,
    allow_private: bool = False,
    tags: list[str] | tuple[str, ...] = (),
    delay_s: float = 0.0,
) -> dict[str, Any]:
    if not robots_allowed(url, allow_private=allow_private):
        return {"feed": url, "ok": False, "reason": "robots.txt disallows this path", "entries": 0, "added": 0}
    fetched = fetch_url(url, allow_private=allow_private)
    if fetched["status"] != 200:
        return {"feed": url, "ok": False, "reason": f"HTTP {fetched['status']}", "entries": 0, "added": 0}
    entries = parse_feed(fetched["body"])
    added = 0
    duplicates = 0
    failures = []
    for entry in entries[:limit]:
        body = extract_text(entry["summary"]) if "<" in entry["summary"] else entry["summary"]
        if len(body.strip()) < 20:
            continue
        try:
            written = store.add(
                body,
                source=entry["link"] or url,
                title=entry["title"],
                tags=list(tags),
            )
        except Exception as exc:  # noqa: BLE001 - one bad entry must not stop the feed
            failures.append({"title": entry["title"], "error": str(exc)})
            continue
        if written["created"]:
            added += 1
        else:
            duplicates += 1
        if delay_s:
            time.sleep(delay_s)
    return {
        "feed": url,
        "ok": True,
        "entries": len(entries),
        "added": added,
        "duplicates": duplicates,
        "failures": failures,
        "elapsed_ms": fetched["elapsed_ms"],
    }
