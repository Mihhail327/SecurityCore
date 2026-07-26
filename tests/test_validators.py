import pytest
from securitycore.validators.email_validator import validate_email, is_email, ensure_email
from securitycore.validators.url_validator import validate_url, is_valid_url, ensure_url
from securitycore.validators.ip_validator import validate_ip, validate_ipv4, validate_ipv6, is_ipv4
from securitycore.validators.password_validator import validate_password, is_password_secure, ensure_password
from securitycore._internal.error import ValidationError


def test_email_validation():
    assert is_email("user@example.com") is True
    assert is_email("invalid-email") is False
    assert validate_email("test.user+tag@domain.co.uk") == "test.user+tag@domain.co.uk"

    with pytest.raises(ValidationError):
        validate_email("bad_email@")

    assert ensure_email("valid@domain.com") == "valid@domain.com"


def test_url_validation():
    assert is_valid_url("https://example.com/path?q=1") is True
    assert is_valid_url("ftp://example.com") is False

    assert validate_url("http://localhost:8000/api") == "http://localhost:8000/api"

    with pytest.raises(ValidationError):
        validate_url("not-a-url")

    assert ensure_url("https://github.com") == "https://github.com"


def test_ip_validation():
    assert is_ipv4("192.168.1.1") is True
    assert is_ipv4("256.256.256.256") is False

    assert validate_ipv4("10.0.0.1") == "10.0.0.1"
    with pytest.raises(ValidationError):
        validate_ipv4("999.1.1.1")

    assert validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    with pytest.raises(ValidationError):
        validate_ipv6("invalid:ipv6:address")

    assert validate_ip("127.0.0.1") == "127.0.0.1"
    assert validate_ip("::1") == "::1"
    with pytest.raises(ValidationError):
        validate_ip("bad_ip")


def test_password_validation():
    strong_pwd = "P@ssw0rd2026!"
    assert is_password_secure(strong_pwd) is True
    assert is_password_secure("weak") is False

    assert validate_password(strong_pwd) == strong_pwd

    with pytest.raises(ValidationError):
        validate_password("short")

    with pytest.raises(ValidationError):
        validate_password("PasswordWithoutDigits!")

    assert ensure_password(strong_pwd) == strong_pwd
