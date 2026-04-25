import pytest
from securitycore.protection.xss import sanitize_xss, ensure_no_xss, SafeString
from securitycore.protection.sql import sanitize_sql_input, ensure_no_sql_injection
from securitycore._internal.error import SecurityViolationError


def test_sanitize_xss():
    dirty_html = (
        '<script>alert("xss")</script><p>Hello <a href="http://test.com">World</a></p>'
    )

    # Дефолтная очистка (разрешает некоторые теги, удаляет опасные)
    clean = sanitize_xss(dirty_html)
    assert isinstance(clean, SafeString)
    assert "<script" not in clean
    assert "<p>Hello" in clean

    # Строгая очистка (только текст)
    strict_clean = sanitize_xss(dirty_html, strict=True)
    assert "Hello" in strict_clean
    assert "<p>" not in strict_clean


def test_ensure_no_xss():
    with pytest.raises(SecurityViolationError):
        ensure_no_xss('<img src="x" onerror="alert(1)">')

    # Должно пройти
    ensure_no_xss("<p>Just a text</p>")


def test_ensure_no_sql_injection():
    with pytest.raises(SecurityViolationError):
        ensure_no_sql_injection("1; DROP TABLE users")

    with pytest.raises(SecurityViolationError):
        ensure_no_sql_injection("admin' OR 1=1")

    # Нормальный ввод
    ensure_no_sql_injection("O'Connor")


def test_sanitize_sql_input():
    # Удаляет опасные комменты
    clean = sanitize_sql_input("user -- comment")
    assert clean == "user  comment"
