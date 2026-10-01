from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

from assessment_collector.models import ModuleResult
from assessment_collector.utils import (create_archive, create_output_directory,
                                        sanitize_filename, sha256_file, write_manifest)


def test_sanitize_filename():
    assert sanitize_filename(' Internal: Scan/One? ') == "Internal__Scan_One"
    assert sanitize_filename("...") == "unnamed"


def test_output_archive_hash_and_manifest(tmp_path: Path):
    root = create_output_directory(tmp_path, datetime(2026, 9, 30, 10, 30))
    evidence = root / "evidence.txt"
    evidence.write_text("abc")
    assert sha256_file(evidence) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    manifest = write_manifest(root, "2026-09-30T10:30:00Z", ["demo"], {"demo": ModuleResult(True)})
    assert '"sha256"' in manifest.read_text()
    archive = create_archive(root)
    with ZipFile(archive) as zipped:
        assert f"{root.name}/manifest.json" in zipped.namelist()
