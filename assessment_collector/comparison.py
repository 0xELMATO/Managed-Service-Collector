from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tempfile
import zipfile
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree


IGNORED_PARTS = {"logs", "manifest.json", "comparison.json", "comparison.txt"}
TEXT_SUFFIXES = {".txt", ".log", ".md", ".out"}
XML_SUFFIXES = {".xml", ".nessus"}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TIMESTAMP_PREFIX = re.compile(r"^(?:\d{8,14}[_-])+")


@dataclass(slots=True)
class Evidence:
    root: Path
    temporary: tempfile.TemporaryDirectory[str] | None = None

    def close(self) -> None:
        if self.temporary:
            self.temporary.cleanup()


def _safe_extract(archive: Path) -> Evidence:
    temporary = tempfile.TemporaryDirectory(prefix="assessment_compare_")
    root = Path(temporary.name)
    total = 0
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            relative = PurePosixPath(member.filename)
            if relative.is_absolute() or ".." in relative.parts:
                temporary.cleanup()
                raise ValueError(f"Unsafe ZIP member: {member.filename}")
            if member.file_size > 250 * 1024 * 1024:
                temporary.cleanup()
                raise ValueError(f"ZIP member is too large to compare: {member.filename}")
            total += member.file_size
            if total > 2 * 1024 * 1024 * 1024:
                temporary.cleanup()
                raise ValueError("ZIP expands beyond the 2 GiB comparison limit")
        zipped.extractall(root)
    children = [path for path in root.iterdir() if path.is_dir()]
    evidence_root = children[0] if len(children) == 1 and not any(path.is_file() for path in root.iterdir()) else root
    return Evidence(evidence_root, temporary)


def open_evidence(path: Path) -> Evidence:
    path = path.expanduser().resolve()
    if path.is_dir():
        return Evidence(path)
    if path.is_file() and zipfile.is_zipfile(path):
        return _safe_extract(path)
    raise ValueError(f"Assessment path is neither a directory nor a ZIP archive: {path}")


def _inventory(root: Path) -> dict[str, Path]:
    result = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        comparison_name = "/".join(TIMESTAMP_PREFIX.sub("", part) for part in relative.parts)
        if comparison_name in result:
            comparison_name = relative.as_posix()
        result[comparison_name] = path
    return result


def _canonical_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonical_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_canonical_json(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def _canonical_xml_element(element: ElementTree.Element) -> tuple[Any, ...]:
    text = " ".join((element.text or "").split())
    attributes = tuple(sorted(element.attrib.items()))
    children = sorted((_canonical_xml_element(child) for child in element), key=repr)
    return element.tag, attributes, text, tuple(children)


def _canonical_csv(data: bytes) -> Counter[tuple[tuple[str, str], ...]]:
    text = data.decode("utf-8-sig", "replace")
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames:
        return Counter(tuple(sorted((key.strip(), (value or "").strip()) for key, value in row.items()))
                       for row in reader)
    return Counter()


def _canonical_text(data: bytes) -> Counter[str]:
    text = ANSI_ESCAPE.sub("", data.decode("utf-8", "replace"))
    return Counter(line for raw in text.splitlines() if (line := " ".join(raw.split())))


def _canonical_zip(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        for member in zipped.infolist():
            if member.is_dir() or member.file_size > 100 * 1024 * 1024:
                continue
            name = "/".join(TIMESTAMP_PREFIX.sub("", part) for part in PurePosixPath(member.filename).parts)
            content = zipped.read(member)
            result[name] = _semantic_digest(content, Path(name).suffix.lower())
    return result


def _semantic_value(data: bytes, suffix: str) -> Any:
    try:
        if suffix == ".json":
            return _canonical_json(json.loads(data.decode("utf-8-sig")))
        if suffix == ".csv":
            return _canonical_csv(data)
        if suffix in XML_SUFFIXES:
            return _canonical_xml_element(ElementTree.fromstring(data))
        if suffix in TEXT_SUFFIXES:
            return _canonical_text(data)
        if suffix == ".zip":
            return _canonical_zip(data)
    except (ValueError, UnicodeError, ElementTree.ParseError, zipfile.BadZipFile):
        pass
    return hashlib.sha256(data).hexdigest()


def _semantic_digest(data: bytes, suffix: str) -> str:
    canonical = _semantic_value(data, suffix)
    def stable(value: Any) -> Any:
        if isinstance(value, Counter):
            entries = [(stable(key), count) for key, count in value.items()]
            return "counter", tuple(sorted(entries, key=repr))
        if isinstance(value, dict):
            return "dict", tuple((key, stable(item)) for key, item in sorted(value.items()))
        if isinstance(value, (list, tuple)):
            return type(value).__name__, tuple(stable(item) for item in value)
        return value
    return hashlib.sha256(repr(stable(canonical)).encode("utf-8", "replace")).hexdigest()


def _json_changes(old: Any, new: Any, path: str = "$") -> list[str]:
    """Return stable JSON paths whose values differ after order normalization."""
    old, new = _canonical_json(old), _canonical_json(new)
    if type(old) is not type(new):
        return [path]
    if isinstance(old, dict):
        changes: list[str] = []
        for key in sorted(set(old) | set(new)):
            child = f"{path}.{key}"
            if key not in old or key not in new:
                changes.append(child)
            else:
                changes.extend(_json_changes(old[key], new[key], child))
        return changes
    if isinstance(old, list):
        return [] if old == new else [path]
    return [] if old == new else [path]


def _counter_delta(old: Counter[Any], new: Counter[Any]) -> dict[str, list[dict[str, Any]]]:
    def entries(counter: Counter[Any]) -> list[dict[str, Any]]:
        return [{"value": repr(value)[:500], "count": count}
                for value, count in sorted(counter.items(), key=lambda item: repr(item[0]))[:200]]
    return {"removed": entries(old - new), "added": entries(new - old)}


def _change_detail(old_data: bytes, new_data: bytes, suffix: str) -> dict[str, Any]:
    """Describe useful semantic deltas without treating reordered records as changes."""
    try:
        if suffix in TEXT_SUFFIXES:
            return {"kind": "text-lines", **_counter_delta(_canonical_text(old_data),
                                                             _canonical_text(new_data))}
        if suffix == ".csv":
            return {"kind": "csv-rows", **_counter_delta(_canonical_csv(old_data),
                                                           _canonical_csv(new_data))}
        if suffix == ".json":
            old_json = json.loads(old_data.decode("utf-8-sig"))
            new_json = json.loads(new_data.decode("utf-8-sig"))
            paths = _json_changes(old_json, new_json)
            return {"kind": "json-paths", "changed_paths": paths[:200],
                    "truncated": len(paths) > 200}
    except (ValueError, UnicodeError):
        pass
    return {"kind": "content", "note": "Semantic content differs; inspect both artifacts."}


def compare_assessments(previous: Path, current: Path) -> dict[str, Any]:
    with ExitStack() as stack:
        old = open_evidence(previous)
        new = open_evidence(current)
        stack.callback(old.close)
        stack.callback(new.close)
        old_files, new_files = _inventory(old.root), _inventory(new.root)
        old_names, new_names = set(old_files), set(new_files)
        added = sorted(new_names - old_names)
        removed = sorted(old_names - new_names)
        changed, unchanged = [], []
        details: dict[str, dict[str, Any]] = {}
        for name in sorted(old_names & new_names):
            old_data, new_data = old_files[name].read_bytes(), new_files[name].read_bytes()
            suffix = Path(name).suffix.lower()
            if _semantic_digest(old_data, suffix) == _semantic_digest(new_data, suffix):
                unchanged.append(name)
            else:
                changed.append(name)
                details[name] = _change_detail(old_data, new_data, suffix)
        return {
            "previous": str(previous.expanduser().resolve()),
            "current": str(current.expanduser().resolve()),
            "summary": {"added": len(added), "removed": len(removed),
                        "changed": len(changed), "unchanged": len(unchanged)},
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "details": details,
            "comparison_notes": [
                "JSON arrays, CSV rows, XML child elements, and text lines are compared without ordering.",
                "PDFs and unknown binary formats are compared by SHA-256 content hash.",
                "Logs, manifests, and prior comparison reports are excluded.",
            ],
        }


def write_comparison(result: dict[str, Any], output_directory: Path) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "comparison.json"
    text_path = output_directory / "comparison.txt"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = result["summary"]
    lines = [
        "Assessment comparison",
        f"Previous: {result['previous']}",
        f"Current : {result['current']}",
        "",
        f"Added: {summary['added']}  Removed: {summary['removed']}  "
        f"Changed: {summary['changed']}  Unchanged: {summary['unchanged']}",
    ]
    for category in ("added", "removed", "changed"):
        lines.extend(["", category.title() + ":"])
        lines.extend(f"  - {name}" for name in result[category])
        if not result[category]:
            lines.append("  (none)")
    if result.get("details"):
        lines.extend(["", "Change details:"])
        for name, detail in result["details"].items():
            lines.append(f"  {name} [{detail['kind']}]")
            if detail["kind"] == "json-paths":
                lines.extend(f"    changed: {path}" for path in detail["changed_paths"])
            elif detail["kind"] in {"text-lines", "csv-rows"}:
                for category in ("removed", "added"):
                    lines.extend(f"    {category}: {entry['value']} (x{entry['count']})"
                                 for entry in detail[category])
            else:
                lines.append(f"    {detail['note']}")
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, text_path
