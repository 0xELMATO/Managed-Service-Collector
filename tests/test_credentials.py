from assessment_collector.credentials import Redactor


def test_redactor_removes_longest_credentials():
    redactor = Redactor(["secret", "CONTOSO\\alice", "alice"])
    text = redactor.redact("CONTOSO\\alice used secret")
    assert "alice" not in text
    assert "secret" not in text
