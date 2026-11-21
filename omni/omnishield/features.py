"""The 500-feature ledger, with evidence that is checked rather than claimed.

Statuses:
  implemented     - a function exists and a test exercises it
  partial         - a component exists but the feature is narrower than named
  external        - needs a model, service or device that is not in this repo
  not_implemented - a testable definition exists, no code yet
  undefined       - no testable definition exists
  refused         - deliberately not built
  duplicate       - the same feature as another id
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "features" / "catalog.json"

STATUSES = (
    "implemented",
    "partial",
    "external",
    "not_implemented",
    "undefined",
    "refused",
    "duplicate",
)
REASON_REQUIRED = ("external", "not_implemented", "undefined", "refused", "duplicate")


class CatalogError(Exception):
    pass


@dataclass(frozen=True)
class Feature:
    id: int
    group: str
    group_sw: str
    name: str
    name_sw: str
    status: str
    evidence: str
    reason: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Feature:
        return cls(
            id=int(raw["id"]),
            group=str(raw["group"]),
            group_sw=str(raw["group_sw"]),
            name=str(raw["name"]),
            name_sw=str(raw["name_sw"]),
            status=str(raw["status"]),
            evidence=str(raw.get("evidence", "")),
            reason=str(raw.get("reason", "")),
        )


def load(path: str | Path | None = None) -> list[Feature]:
    target = Path(path) if path is not None else CATALOG
    if not target.is_file():
        raise CatalogError(f"catalog not found: {target}")
    document = json.loads(target.read_text(encoding="utf-8"))
    return [Feature.from_dict(raw) for raw in document["features"]]


def _check_evidence(evidence: str) -> str | None:
    if not evidence:
        return "implemented entry has no evidence"
    if "::" in evidence:
        location, _, symbol = evidence.partition("::")
    else:
        location, symbol = evidence, ""
    path = ROOT / location
    if not path.exists():
        return f"evidence path does not exist: {location}"
    if symbol:
        leaf = symbol.split("::")[-1]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"cannot read {location}: {exc}"
        if leaf not in text:
            return f"symbol {leaf!r} not found in {location}"
    return None


def validate(features: Iterable[Feature] | None = None) -> list[str]:
    items = list(features) if features is not None else load()
    problems: list[str] = []
    if len(items) != 500:
        problems.append(f"expected 500 features, found {len(items)}")
    if [feature.id for feature in items] != list(range(1, len(items) + 1)):
        problems.append("ids are not sequential from 1")

    groups: dict[str, int] = {}
    for feature in items:
        groups[feature.group] = groups.get(feature.group, 0) + 1
        if feature.status not in STATUSES:
            problems.append(f"#{feature.id}: unknown status {feature.status!r}")
        if feature.status in REASON_REQUIRED and not feature.reason:
            problems.append(f"#{feature.id}: {feature.status} needs a reason")
        if feature.status == "implemented":
            failure = _check_evidence(feature.evidence)
            if failure:
                problems.append(f"#{feature.id}: {failure}")
        if feature.status == "duplicate":
            if "#" not in feature.reason:
                problems.append(f"#{feature.id}: duplicate reason must name the target id")
            else:
                raw = feature.reason.split("#", 1)[1].split()[0].rstrip(".")
                if not raw.isdigit() or not (1 <= int(raw) <= 500):
                    problems.append(f"#{feature.id}: duplicate target {raw!r} is not a valid id")
                elif int(raw) == feature.id:
                    problems.append(f"#{feature.id}: duplicate of itself")
    if len(groups) != 20:
        problems.append(f"expected 20 groups, found {len(groups)}")
    for name, count in groups.items():
        if count != 25:
            problems.append(f"group {name!r} has {count} features, expected 25")
    return problems


def audit(features: Iterable[Feature] | None = None) -> dict[str, Any]:
    items = list(features) if features is not None else load()
    counts: dict[str, int] = {status: 0 for status in STATUSES}
    for feature in items:
        counts[feature.status] += 1
    by_group: dict[str, dict[str, int]] = {}
    for feature in items:
        bucket = by_group.setdefault(feature.group, {status: 0 for status in STATUSES})
        bucket[feature.status] += 1
    problems = validate(items)
    built = counts["implemented"] + counts["partial"]
    return {
        "total": len(items),
        "counts": counts,
        "built": built,
        "coverage": round(built / len(items), 4) if items else 0.0,
        "groups": by_group,
        "problems": problems,
        "ok": not problems,
    }


def _items(features: Iterable[Feature] | None) -> list[Feature]:
    return list(features) if features is not None else load()


def by_status(status: str, features: Iterable[Feature] | None = None) -> list[Feature]:
    if status not in STATUSES:
        raise CatalogError(f"unknown status: {status}")
    return [feature for feature in _items(features) if feature.status == status]


def by_group(group: str, features: Iterable[Feature] | None = None) -> list[Feature]:
    items = [feature for feature in _items(features) if feature.group == group]
    if not items:
        raise CatalogError(f"unknown group: {group}")
    return items


def get(identifier: int, features: Iterable[Feature] | None = None) -> Feature:
    for feature in _items(features):
        if feature.id == identifier:
            return feature
    raise CatalogError(f"no feature with id {identifier}")
