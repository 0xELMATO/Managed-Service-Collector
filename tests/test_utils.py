from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

from assessment_collector.models import ModuleResult
from assessment_collector.utils import (create_archive, create_output_directory,
                                        normalize_output_tree, sanitize_filename,
                                        sha256_file, write_manifest)


def test_sanitize_filename():
    assert sanitize_filename(' Internal: Scan/One? ') == "Internal__Scan_One"
    assert sanitize_filename("...") == "unnamed"
    assert sanitize_filename("Current SJD server range (Windows / RedHat)") == \
        "Current_SJD_server_range_(Windows___RedHat)"
    assert sanitize_filename("CON") == "_CON"


def test_normalize_output_tree_renames_external_tool_files(tmp_path: Path):
    root = tmp_path / "assessment"
    folder = root / "Certipy results: current"
    folder.mkdir(parents=True)
    original = folder / "report: domain?.json"
    original.write_text("{}")
    normalize_output_tree(root)
    assert (root / "Certipy_results__current" / "report__domain.json").is_file()


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
