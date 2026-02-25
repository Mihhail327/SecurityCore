import pytest
from securitycore.crypto.crypto_utils import hash_data, sign_data, verify_signature
from securitycore.crypto.keygen import generate_hex_key
from securitycore.crypto.tokens import generate_token, verify_token


# --- Тесты хэширования ---

def test_hash_data_sha256():
    """Проверяем SHA256 (дефолтный алгоритм)."""
    result = hash_data("test")
    assert isinstance(result, str)
    assert len(result) == 64
    # Проверка детерминированности
    assert result == hash_data("test")


def test_hash_data_md5():
    """Проверяем MD5 (через явное указание)."""
    result = hash_data("test", algorithm="md5")
    assert isinstance(result, str)
    assert len(result) == 32


# --- Тесты ключей и токенов ---

def test_generate_hex_key():
    """Проверяем генерацию HEX-ключей."""
    length = 16
    key = generate_hex_key(length)
    assert isinstance(key, str)
    assert len(key) == length * 2  # Каждому байту соответствует 2 hex-символа


def test_token_lifecycle():
    """Проверяем полный цикл жизни токена."""
    token = generate_token(length=32)
    assert isinstance(token, str)
    assert len(token) > 20

    # Проверяем верификацию
    assert verify_token(token) is True
    assert verify_token("invalid_token") is False


# --- Тесты подписей (HMAC) ---

def test_signature_flow():
    """Проверяем подпись и проверку данных."""
    key = "super-secret-key"
    data = "important-message"

    signature = sign_data(data, key)
    assert isinstance(signature, str)

    # Валидная подпись
    assert verify_signature(data, signature, key) is True
    # Подмененные данные
    assert verify_signature("hacked-message", signature, key) is False
    # Неверный ключ
    assert verify_signature(data, signature, "wrong-key") is False


def test_hash_unsupported_algorithm():
    """Проверяем реакцию на неподдерживаемый алгоритм."""
    with pytest.raises(ValueError):
        hash_data("test", algorithm="super-fast-hash")