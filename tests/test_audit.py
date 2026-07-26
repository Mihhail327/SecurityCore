import logging
import pytest
from securitycore.audit.audit_logger import audit
from securitycore.audit.json_logger import audit_json
from securitycore._internal.error import AuditError


def test_audit_logging(caplog):
    with caplog.at_level(logging.INFO):
        audit("user_login", {"user_id": 42, "ip": "127.0.0.1"})

    assert "user_login" in caplog.text
    assert "user_id=42" in caplog.text
    assert "ip=127.0.0.1" in caplog.text


def test_audit_empty_event():
    with pytest.raises(AuditError):
        audit("")


def test_audit_truncation(caplog):
    huge_details = {f"key_{i}": "x" * 500 for i in range(10)}
    with caplog.at_level(logging.INFO):
        audit("huge_event", huge_details)

    assert "[TRUNCATED]" in caplog.text


def test_audit_json_logging(caplog):
    with caplog.at_level(logging.INFO):
        audit_json("user_action", {"action": "delete", "target": "item_55"})

    assert '"event":"user_action"' in caplog.text
    assert '"action":"delete"' in caplog.text


def test_audit_json_truncation(caplog):
    huge_details = {f"k_{i}": "v" * 100 for i in range(100)}
    with caplog.at_level(logging.INFO):
        audit_json("huge_json_event", huge_details)

    assert "[TRUNCATED]" in caplog.text
