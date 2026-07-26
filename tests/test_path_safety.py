import pytest
from securitycore.protection.path_safety import ensure_no_path_traversal, ensure_safe_filename, ensure_safe_path
from securitycore._internal.error import SecurityViolationError


def test_path_traversal_detection():
    # Валидный относительный путь
    ensure_no_path_traversal("uploads/images/photo.png")

    with pytest.raises(SecurityViolationError):
        ensure_no_path_traversal("../etc/passwd")

    with pytest.raises(SecurityViolationError):
        ensure_no_path_traversal("uploads/%2e%2e/secret.txt")

    with pytest.raises(SecurityViolationError):
        ensure_no_path_traversal("file\x00.txt")


def test_safe_filename():
    ensure_safe_filename("document.pdf")
    ensure_safe_filename("avatar_123.jpg")

    # Запрещенные расширения
    with pytest.raises(SecurityViolationError):
        ensure_safe_filename("malware.exe")

    with pytest.raises(SecurityViolationError):
        ensure_safe_filename("script.sh")

    # Запрещенные системные имена Windows
    with pytest.raises(SecurityViolationError):
        ensure_safe_filename("CON.txt")

    with pytest.raises(SecurityViolationError):
        ensure_safe_filename("NUL")


def test_safe_path():
    ensure_safe_path("data/reports/2026_summary.csv")

    with pytest.raises(SecurityViolationError):
        ensure_safe_path("data/../../system32/cmd.exe")
