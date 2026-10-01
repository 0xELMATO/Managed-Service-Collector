from pathlib import Path
from unittest.mock import Mock, patch
import warnings

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

from assessment_collector.nessus import EXPORTS, NessusClient, NessusError


def response(payload=None, status=200):
    result = Mock()
    result.json.return_value = payload or {}
    result.raise_for_status.side_effect = None if status < 400 else requests.HTTPError(response=result)
    result.status_code = status
    return result


def test_api_error_is_wrapped():
    session = Mock()
    session.request.side_effect = requests.Timeout("late")
    with pytest.raises(NessusError, match="request failed"):
        NessusClient("https://nessus", session=session).list_scans()


@patch("assessment_collector.nessus.time.sleep", return_value=None)
def test_export_polling_waits_until_ready(_sleep):
    session = Mock()
    session.request.side_effect = [response({"status": "loading"}), response({"status": "ready"})]
    NessusClient("https://nessus", session=session).wait_for_export(7, 9, poll_interval=0, poll_timeout=3)
    assert session.request.call_count == 2


def test_export_payloads_include_two_pdf_layouts():
    assert EXPORTS["pdf_host"].payload["chapters"] == "vuln_hosts_summary"
    assert EXPORTS["pdf_plugin"].payload["chapters"] == "vuln_by_plugin"


def test_insecure_request_warning_is_scoped_and_suppressed():
    session = Mock()

    def emit_warning(*_args, **_kwargs):
        warnings.warn("unverified", InsecureRequestWarning)
        return response({"scans": []})

    session.request.side_effect = emit_warning
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert NessusClient("https://nessus", verify_tls=False, session=session).list_scans() == []
    assert caught == []


def test_other_warning_categories_are_not_suppressed():
    session = Mock()

    def emit_warning(*_args, **_kwargs):
        warnings.warn("application warning", RuntimeWarning)
        return response({"scans": []})

    session.request.side_effect = emit_warning
    with pytest.warns(RuntimeWarning, match="application warning"):
        NessusClient("https://nessus", verify_tls=False, session=session).list_scans()
