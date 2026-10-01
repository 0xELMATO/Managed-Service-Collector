from pathlib import Path

import pytest

from assessment_collector.credentials import Redactor
from assessment_collector.models import Credentials
from assessment_collector.netexec import NetExecCollector
from assessment_collector.pingcastle import PingCastleCollector


def test_netexec_command_is_argument_array(tmp_path: Path):
    collector = NetExecCollector(tmp_path, Redactor())
    command = collector.build_command("nxc", "10.0.0.0/24", Credentials("ACME", "audit", "pw"))
    assert command == ["nxc", "smb", "10.0.0.0/24", "-u", "audit", "-p", "pw", "-d", "ACME"]


def test_pingcastle_without_pywinrm_has_clear_error(tmp_path: Path, monkeypatch):
    collector = PingCastleCollector(tmp_path, "server", 5985, Credentials("D", "u", "p"))
    monkeypatch.setitem(__import__("sys").modules, "winrm", None)
    with pytest.raises(RuntimeError, match="pywinrm not installed"):
        collector.connect()


def test_missing_netexec(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("assessment_collector.netexec.find_tool", lambda *_: None)
    result = NetExecCollector(tmp_path, Redactor()).collect("127.0.0.1", Credentials("", "u", "p"))
    assert not result.success and "not found" in result.reason
