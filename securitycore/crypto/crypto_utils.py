import hashlib
import hmac
import secrets

from securitycore._internal.constants import (
    DEFAULT_SALT_LENGTH,
    DEFAULT_ENCODING,
    HASH_ITERATIONS,
    HASH_ALGORITHM,
    DEFAULT_TOKEN_LENGTH,
)
from securitycore._internal.error import CryptoError


# Генерация криптографически стойкой соли
def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    """
    Возвращает криптографически стойкую соль.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина соли должна быть положительным числом")

    try:
        return secrets.token_bytes(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации соли: {exc}")


# Хэширование данных PBKDF2-HMAC
def hash_data(data: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Хэширует строку с использованием PBKDF2-HMAC.
    Возвращает (salt, hash).
    """
    if not isinstance(data, str):
        raise CryptoError("Данные для хэширования должны быть строкой")

    salt = salt or generate_salt()

    try:
        hashed = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            data.encode(DEFAULT_ENCODING),
            salt,
            HASH_ITERATIONS,
        )
        return salt, hashed
    except Exception as exc:
        raise CryptoError(f"Ошибка хэширования данных: {exc}")


# Проверка соответствия данных и хэша
def verify_hash(data: str, salt: bytes, expected_hash: bytes) -> bool:
    """
    Проверяет, соответствует ли строка ранее вычисленному хэшу.
    """
    if not isinstance(data, str):
        return False

    try:
        _, new_hash = hash_data(data, salt)
        return hmac.compare_digest(new_hash, expected_hash)
    except Exception:
        return False


# Генерация безопасного токена
def generate_token(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """
    Возвращает криптографически стойкий токен в hex-формате.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина токена должна быть положительной")

    try:
        return secrets.token_hex(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


# Подпись данных HMAC
def sign_data(data: str, key: bytes) -> bytes:
    """
    Создаёт HMAC-подпись данных.
    """
    if not isinstance(data, str):
        raise CryptoError("Данные для подписи должны быть строкой")

    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("Ключ для подписи должен быть байтовым")

    try:
        return hmac.new(key, data.encode(DEFAULT_ENCODING), HASH_ALGORITHM).digest()
    except Exception as exc:
        raise CryptoError(f"Ошибка подписи данных: {exc}")


# Проверка подписи
def verify_signature(data: str, key: bytes, signature: bytes) -> bool:
    """
    Проверяет корректность HMAC-подписи.
    """
    if not isinstance(signature, (bytes, bytearray)):
        return False

    try:
        expected = sign_data(data, key)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False