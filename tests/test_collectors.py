from pathlib import Path

import pytest

from assessment_collector.credentials import Redactor
from assessment_collector.models import Credentials
from assessment_collector.netexec import NetExecCollector
from assessment_collector.pingcastle import PingCastleCollector


def test_netexec_command_is_argument_array(tmp_path: Path):
    collector = NetExecCollector(tmp_path, Redactor())
    command = collector.build_command("nxc", tmp_path / "scope.txt", Credentials("ACME", "audit", "pw"))
    assert command == ["nxc", "smb", str(tmp_path / "scope.txt"), "-u", "audit", "-p", "pw", "-d", "ACME"]


def test_pingcastle_without_pywinrm_has_clear_error(tmp_path: Path, monkeypatch):
    collector = PingCastleCollector(tmp_path, "server", 5985, Credentials("D", "u", "p"))
    monkeypatch.setitem(__import__("sys").modules, "winrm", None)
    with pytest.raises(RuntimeError, match="pywinrm not installed"):
        collector.connect()


def test_missing_netexec(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("assessment_collector.netexec.find_tool", lambda *_: None)
    result = NetExecCollector(tmp_path, Redactor()).collect(tmp_path / "scope.txt", Credentials("", "u", "p"))
    assert not result.success and "not found" in result.reason


def test_bloodhound_name_server_argument(tmp_path: Path):
    from assessment_collector.bloodhound import BloodHoundCollector

    command = BloodHoundCollector(tmp_path, Redactor()).build_command(
        "bloodhound-python", "-u -p -d -c -dc -ns", Credentials("ACME", "audit", "pw"),
        "dc01.acme.test", "All", "10.0.0.53",
    )
    assert command[-4:] == ["-dc", "dc01.acme.test", "-ns", "10.0.0.53"]


def test_pingcastle_progress_clixml_is_not_reported_as_an_error():
    from assessment_collector.pingcastle import _powershell_error

    progress = (b'#< CLIXML\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
                b'<Obj S="progress"><MS><S N="Message">Preparing modules</S></MS></Obj></Objs>')
    assert _powershell_error(progress) == ""
