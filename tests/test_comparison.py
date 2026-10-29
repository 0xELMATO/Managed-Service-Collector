import json
import zipfile
from pathlib import Path

from assessment_collector.comparison import compare_assessments, write_comparison


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    previous, current = tmp_path / "previous", tmp_path / "current"
    previous.mkdir()
    current.mkdir()
    return previous, current


def test_text_line_reordering_is_not_a_change(tmp_path: Path):
    previous, current = _roots(tmp_path)
    (previous / "findings.txt").write_text("host-a disabled\nhost-b enabled\n")
    (current / "findings.txt").write_text("host-b enabled\n\nhost-a   disabled\n")
    result = compare_assessments(previous, current)
    assert result["changed"] == []
    assert result["unchanged"] == ["findings.txt"]


def test_structured_row_and_array_reordering_is_not_a_change(tmp_path: Path):
    previous, current = _roots(tmp_path)
    (previous / "hosts.csv").write_text("host,status\na,off\nb,on\n")
    (current / "hosts.csv").write_text("status,host\non,b\noff,a\n")
    (previous / "data.json").write_text(json.dumps({"items": [{"id": 1}, {"id": 2}]}))
    (current / "data.json").write_text(json.dumps({"items": [{"id": 2}, {"id": 1}]}))
    result = compare_assessments(previous, current)
    assert result["changed"] == []
    assert set(result["unchanged"]) == {"hosts.csv", "data.json"}


def test_xml_child_reordering_is_not_a_change(tmp_path: Path):
    previous, current = _roots(tmp_path)
    (previous / "scan.nessus").write_text("<root><host name='a'/><host name='b'/></root>")
    (current / "scan.nessus").write_text("<root>\n <host name='b'/> <host name='a'/>\n</root>")
    result = compare_assessments(previous, current)
    assert result["changed"] == []


def test_comparison_reports_real_changes_and_writes_reports(tmp_path: Path):
    previous, current = _roots(tmp_path)
    (previous / "removed.txt").write_text("old")
    (previous / "same.json").write_text('{"enabled": false}')
    (current / "added.txt").write_text("new")
    (current / "same.json").write_text('{"enabled": true}')
    result = compare_assessments(previous, current)
    assert result["summary"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 0}
    json_path, text_path = write_comparison(result, current)
    assert json_path.is_file() and "same.json" in text_path.read_text()
    assert result["details"]["same.json"]["changed_paths"] == ["$.enabled"]


def test_text_change_details_do_not_report_moved_lines(tmp_path: Path):
    previous, current = _roots(tmp_path)
    (previous / "findings.txt").write_text("stable\nremoved finding\n")
    (current / "findings.txt").write_text("added finding\nstable\n")
    detail = compare_assessments(previous, current)["details"]["findings.txt"]
    assert detail["removed"] == [{"value": "'removed finding'", "count": 1}]
    assert detail["added"] == [{"value": "'added finding'", "count": 1}]


def test_timestamped_zip_member_names_are_matched(tmp_path: Path):
    previous, current = _roots(tmp_path)
    for path, member in ((previous / "bloodhound.zip", "20260101_users.json"),
                         (current / "bloodhound.zip", "20261029_users.json")):
        with zipfile.ZipFile(path, "w") as output:
            output.writestr(member, '[{"name":"alice"}]')
    result = compare_assessments(previous, current)
    assert result["changed"] == []
