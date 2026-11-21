"""Follow images online, measure them and keep what is new.

Discovery reads feeds for image enclosures and links. Every download goes through
the same guard as the text loop: robots.txt, private-address refusal, a byte cap
and a content-type check. Only PNG is decoded, because that is what this
repository can decode without a codec library.

A perceptual hash decides whether an image has been seen before. New images are
described in words and written to the knowledge store, so the daily loop grows.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .ingest import IngestError, fetch_url, parse_feed
from .knowledge import KnowledgeStore
from .render import Canvas, downsample
from .vision import decode_png

IMAGE_TYPES = ("image/png",)


class ImageryError(Exception):
    pass


def discover_images(feed_url: str, *, limit: int = 20, allow_private: bool = False) -> list[dict[str, Any]]:
    """Read a feed and return image URLs found in enclosures or markup."""
    fetched = fetch_url(feed_url, allow_private=allow_private)
    if fetched["status"] != 200:
        raise ImageryError(f"HTTP {fetched['status']} for {feed_url}")
    entries = parse_feed(fetched["body"])
    found: list[dict[str, Any]] = []
    for entry in entries:
        summary = entry.get("summary", "")
        candidates = re.findall(r'https?://[^\s"\'<>]+?\.(?:png|jpg|jpeg|gif|webp)', summary)
        for candidate in candidates:
            found.append({"url": candidate, "title": entry.get("title", ""), "source": feed_url})
    unique: dict[str, dict[str, Any]] = {}
    for item in found:
        unique.setdefault(item["url"], item)
    return list(unique.values())[:limit]


def fetch_image(url: str, *, allow_private: bool = False, max_bytes: int = 4_000_000) -> dict[str, Any]:
    fetched = fetch_url(url, max_bytes=max_bytes, allow_private=allow_private)
    if fetched["status"] != 200:
        raise ImageryError(f"HTTP {fetched['status']}")
    kind = fetched["content_type"].split(";")[0].strip().lower()
    if kind not in IMAGE_TYPES:
        raise ImageryError(f"unsupported image type {kind or 'unknown'}; only PNG is decoded here")
    try:
        decoded = decode_png(fetched["body"])
    except Exception as exc:
        raise ImageryError(f"cannot decode the PNG: {exc}") from exc
    return {
        "width": decoded["width"],
        "height": decoded["height"],
        "rows": decoded["rows"],
        "bytes": len(fetched["body"]),
        "sha256": hashlib.sha256(fetched["body"]).hexdigest(),
        "elapsed_ms": fetched["elapsed_ms"],
    }


def _luma(pixel: Any) -> float:
    if isinstance(pixel, (list, tuple)):
        return 0.2126 * pixel[0] + 0.7152 * pixel[1] + 0.0722 * pixel[2]
    return float(pixel)


def perceptual_hash(rows: list[list[Any]], *, size: int = 8) -> dict[str, Any]:
    """Average hash: downscale to 8x8 grey and compare every cell to the mean."""
    height, width = len(rows), len(rows[0])
    if height < size or width < size:
        raise ImageryError("the image is smaller than the hash grid")
    cells = []
    for gy in range(size):
        for gx in range(size):
            total = 0.0
            count = 0
            for y in range(gy * height // size, (gy + 1) * height // size):
                for x in range(gx * width // size, (gx + 1) * width // size):
                    total += _luma(rows[y][x])
                    count += 1
            cells.append(total / max(1, count))
    mean = sum(cells) / len(cells)
    bits = 0
    for cell in cells:
        bits = (bits << 1) | (1 if cell >= mean else 0)
    return {"hash": f"{bits:016x}", "bits": bits, "mean": round(mean, 2)}


def hamming(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def image_stats(rows: list[list[Any]]) -> dict[str, Any]:
    height, width = len(rows), len(rows[0])
    total = [0.0, 0.0, 0.0]
    saturation = 0.0
    colours: dict[tuple[int, int, int], int] = {}
    edges = 0.0
    count = 0
    for y in range(height):
        for x in range(width):
            pixel = rows[y][x]
            r, g, b = pixel if isinstance(pixel, (list, tuple)) else (pixel, pixel, pixel)
            total[0] += r
            total[1] += g
            total[2] += b
            high, low = max(r, g, b), min(r, g, b)
            saturation += 0.0 if high == 0 else (high - low) / high
            key = (r // 32 * 32, g // 32 * 32, b // 32 * 32)
            colours[key] = colours.get(key, 0) + 1
            if x and y:
                edges += abs(_luma(pixel) - _luma(rows[y][x - 1])) + abs(_luma(pixel) - _luma(rows[y - 1][x]))
            count += 1
    dominant = max(colours.items(), key=lambda pair: pair[1])
    return {
        "width": width,
        "height": height,
        "mean_rgb": [round(value / count, 1) for value in total],
        "saturation": round(saturation / count, 3),
        "edge_density": round(edges / count, 2),
        "dominant_rgb": list(dominant[0]),
        "dominant_share": round(dominant[1] / count, 3),
        "unique_blocks": len(colours),
    }


def describe(url: str, stats: Mapping[str, Any], digest: Mapping[str, Any], title: str = "") -> str:
    return (
        f"Image {title or url} is {stats['width']}x{stats['height']} with mean RGB "
        f"{stats['mean_rgb']}, saturation {stats['saturation']}, edge density "
        f"{stats['edge_density']} and dominant colour {stats['dominant_rgb']} over "
        f"{stats['unique_blocks']} blocks. Perceptual hash {digest['hash']}."
    )


def contact_sheet(items: Iterable[Mapping[str, Any]], *, columns: int = 4, cell: tuple[int, int] = (120, 90)) -> Canvas:
    entries = [item for item in items if item.get("rows")]
    if not entries:
        raise ImageryError("nothing to put on the contact sheet")
    rows = (len(entries) + columns - 1) // columns
    width = columns * cell[0]
    height = rows * (cell[1] + 18) + 24
    sheet = Canvas(width, height, (18, 22, 32))
    sheet.text(6, 4, f"CONTACT SHEET  {len(entries)} IMAGES", (235, 240, 250))
    for index, item in enumerate(entries):
        column = index % columns
        row = index // columns
        x = column * cell[0] + 4
        y = 24 + row * (cell[1] + 18)
        source = Canvas(item["width"], item["height"])
        for py, line in enumerate(item["rows"]):
            for px, pixel in enumerate(line):
                source.set(px, py, tuple(pixel[:3]) if isinstance(pixel, (list, tuple)) else (pixel, pixel, pixel))
        thumbnail = downsample(source, max(1, source.width // cell[0])) if source.width > cell[0] else source
        for ty in range(min(cell[1], thumbnail.height)):
            for tx in range(min(cell[0], thumbnail.width)):
                sheet.set(x + tx, y + ty, thumbnail.get(tx, ty))
        sheet.text(x, y + cell[1] + 3, f"{index + 1} {item.get('hash', '')[:6]}", (200, 210, 225))
    return sheet


def learn_images(
    urls: Iterable[Mapping[str, Any]],
    store: KnowledgeStore,
    *,
    seen_path: str | Path,
    allow_private: bool = False,
    limit: int = 8,
) -> dict[str, Any]:
    seen_file = Path(seen_path)
    seen: list[dict[str, Any]] = json.loads(seen_file.read_text(encoding="utf-8")) if seen_file.is_file() else []
    known = [int(entry["bits"]) for entry in seen]
    learned = []
    skipped = []
    images = []
    for item in list(urls)[:limit]:
        try:
            image = fetch_image(item["url"], allow_private=allow_private)
        except (ImageryError, IngestError) as exc:
            skipped.append({"url": item["url"], "reason": str(exc)})
            continue
        digest = perceptual_hash(image["rows"])
        nearest = min((hamming(digest["bits"], bits) for bits in known), default=64)
        if nearest <= 5:
            skipped.append({"url": item["url"], "reason": f"already seen, distance {nearest}"})
            continue
        stats = image_stats(image["rows"])
        text = describe(item["url"], stats, digest, item.get("title", ""))
        store.add(text, source=item["url"], title=item.get("title") or item["url"], tags=["image", "visual"])
        known.append(digest["bits"])
        seen.append({"url": item["url"], "bits": digest["bits"], "hash": digest["hash"], "at_ms": int(time.time() * 1000)})
        learned.append({"url": item["url"], "hash": digest["hash"], "stats": stats})
        images.append({**image, "url": item["url"], "hash": digest["hash"], "title": item.get("title", "")})
    seen_file.parent.mkdir(parents=True, exist_ok=True)
    seen_file.write_text(json.dumps(seen, sort_keys=True), encoding="utf-8")
    return {"learned": learned, "skipped": skipped, "images": images}


def daily(
    feeds: Iterable[str],
    store: KnowledgeStore,
    *,
    out_dir: str | Path,
    seen_path: str | Path,
    limit: int = 8,
    allow_private: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    discovered: list[dict[str, Any]] = []
    failures = []
    for feed in feeds:
        try:
            discovered.extend(discover_images(feed, limit=limit, allow_private=allow_private))
        except (ImageryError, IngestError) as exc:
            failures.append({"feed": feed, "reason": str(exc)})
    result = learn_images(discovered, store, seen_path=seen_path, allow_private=allow_private, limit=limit)
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    sheet_path = None
    if result["images"]:
        sheet = contact_sheet(result["images"])
        sheet_path = sheet.save_png(target / "contact-sheet.png")
    document = {
        "feeds": list(feeds),
        "discovered": len(discovered),
        "learned": len(result["learned"]),
        "skipped": result["skipped"],
        "failures": failures,
        "contact_sheet": str(sheet_path) if sheet_path else None,
        "store_items": len(store.items),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    (target / "imagery.jsonl").write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    return document
