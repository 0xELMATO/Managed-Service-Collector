from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path


def sanitize_filename(name: str, fallback: str = "unnamed", max_length: int = 120) -> str:
    value = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", name).strip(" ._")
    value = re.sub(r"\s+", "_", value)
    return (value[:max_length].rstrip(" ._") or fallback)


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for number in range(2, 10_000):
        candidate = path.with_name(f"{path.stem}_{number}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate a unique filename for {path}")


def create_output_directory(parent: Path, now: datetime | None = None) -> Path:
    stamp = (now or datetime.now().astimezone()).strftime("%Y-%m-%d_%H%M%S")
    parent.mkdir(parents=True, exist_ok=True)
    root = unique_path(parent / f"assessment_{stamp}")
    root.mkdir(mode=0o700)
    (root / "logs").mkdir(mode=0o700)
    return root


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_archive(root: Path) -> Path:
    archive = unique_path(root.with_suffix(".zip"))
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as output:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(root.parent))
    return archive


def write_manifest(root: Path, timestamp: str, selected: list[str], results: dict) -> Path:
    manifest_path = root / "manifest.json"
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path != manifest_path:
            files.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size,
                          "sha256": sha256_file(path)})
    payload = {
        "timestamp": timestamp,
        "selected_modules": selected,
        "modules": {name: ("success" if result.success else "failed") for name, result in results.items()},
        "targets": {name: result.targets for name, result in results.items()},
        "details": {name: result.details for name, result in results.items()},
        "files": files,
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def find_tool(*names: str) -> str | None:
    return next((path for name in names if (path := shutil.which(name))), None)


def parse_selection(value: str, maximum: int) -> list[int]:
    selected: set[int] = set()
    for part in value.replace(",", " ").split():
        if "-" in part:
            start, end = (int(item) for item in part.split("-", 1))
            selected.update(range(start, end + 1))
        else:
            selected.add(int(part))
    if not selected or min(selected) < 1 or max(selected) > maximum:
        raise ValueError("selection is outside the displayed range")
    return sorted(selected)
