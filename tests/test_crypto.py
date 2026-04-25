import pytest
from securitycore.crypto.crypto_utils import (
    hash_data,
    verify_hash,
    sign_data,
    verify_signature,
)
from securitycore.crypto.keygen import generate_hex_key
from securitycore.crypto.tokens import create_token_pair, verify_token
from securitycore._internal.error import CryptoError

# --- Тесты хэширования ---


def test_hash_data_pbkdf2():
    """Проверяем PBKDF2 хэширование."""
    result, salt = hash_data("test")
    assert isinstance(result, bytes)
    assert isinstance(salt, bytes)
    # Проверка детерминированности с той же солью
    result2, salt2 = hash_data("test", salt=salt)
    assert result == result2


def test_verify_hash():
    """Проверяем верификацию хэша."""
    result, salt = hash_data("test_password")
    assert verify_hash("test_password", salt, result) is True
    assert verify_hash("wrong_password", salt, result) is False


def test_argon2_hashing():
    """Проверяем хеширование через Argon2id."""
    from securitycore.crypto.crypto_utils import hash_password, verify_password

    password = "SuperSecretPassword123!"
    pwhash = hash_password(password)

    assert pwhash.startswith("$argon2id$")
    assert verify_password(password, pwhash) is True
    assert verify_password("wrong_password", pwhash) is False


# --- Тесты ключей и токенов ---


def test_generate_hex_key():
    """Проверяем генерацию HEX-ключей."""
    length = 16
    key = generate_hex_key(length)
    assert isinstance(key, str)
    assert len(key) == length * 2  # Каждому байту соответствует 2 hex-символа


def test_generate_api_key():
    """Проверяем генерацию API-ключей с префиксом."""
    from securitycore.crypto.keygen import generate_api_key

    key = generate_api_key(16, "test_prefix_")
    assert key.startswith("test_prefix_")
    # Префикс (12) + 16 байт в hex (32) = 44
    assert len(key) == 12 + 32


def test_token_lifecycle():
    """Проверяем полный цикл жизни токена."""
    payload = {"user_id": 123}
    token, key = create_token_pair(payload)
    assert isinstance(token, str)
    assert isinstance(key, bytes)

    # Проверяем верификацию
    decoded = verify_token(token, key)
    assert decoded["user_id"] == 123

    with pytest.raises(CryptoError):
        verify_token("invalid_token", key)


# --- Тесты подписей (HMAC) ---


def test_signature_flow():
    """Проверяем подпись и проверку данных."""
    key = b"super-secret-key"
    data = "important-message"

    signature = sign_data(data, key)
    assert isinstance(signature, bytes)

    # Валидная подпись
    assert verify_signature(data, key, signature) is True
    # Подмененные данные
    assert verify_signature("hacked-message", key, signature) is False
    # Неверный ключ
    assert verify_signature(data, b"wrong-key", signature) is False


def test_sign_data_invalid_types():
    with pytest.raises(CryptoError):
        sign_data("data", "string-key-not-bytes")  # type: ignore
