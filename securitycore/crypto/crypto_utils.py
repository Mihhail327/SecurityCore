import hashlib
import hmac
import secrets

from securitycore._internal.constants import (
    DEFAULT_ENCODING,
    DEFAULT_SALT_LENGTH,
    DEFAULT_TOKEN_LENGTH,
    HASH_ALGORITHM,
    HASH_ITERATIONS,
)
from securitycore._internal.error import CryptoError


def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    """
    Генерирует криптографически стойкую соль.
    Соль используется для усиления хеширования паролей и других секретов.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина соли должна быть положительным числом")

    try:
        return secrets.token_bytes(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации соли: {exc}")


def hash_data(data: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Хеширует данные с помощью PBKDF2-HMAC.
    Возвращает кортеж (хеш, соль)."""
    if not isinstance(data, str):
        raise CryptoError("Данные для хэширования должны быть строкой")

    current_salt: bytes = salt if salt is not None else generate_salt()

    try:
        hashed = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM, data.encode(DEFAULT_ENCODING), current_salt, HASH_ITERATIONS
        )
        return hashed, current_salt
    except Exception as exc:
        raise CryptoError(f"Ошибка хеширования данных: {exc}")


def verify_hash(data: str, salt: bytes, expected_hash: bytes) -> bool:
    """
    Безопасно проверяет соответсвие строки хэшу (защита от timing attacks).
    """
    if (
        not isinstance(data, str)
        or not isinstance(salt, bytes)
        or not isinstance(expected_hash, bytes)
    ):
        return False

    try:
        # Прямое вычисление для максимальной производительности при проверке
        actual_hash = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM, data.encode(DEFAULT_ENCODING), salt, HASH_ITERATIONS
        )
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def generate_token(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """
    Возвращает криптографически стойкий токен в hex-формате.
    Примечание: итоговая строка будет иметь длину length * 2.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина токена должна быть положительной")

    try:
        return secrets.token_hex(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


def sign_data(data: str, key: bytes) -> bytes:
    """
    Создаёт HMAC-подпись данных.
    """
    if not isinstance(data, str):
        raise CryptoError("Данные для подписи должны быть строкой")

    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("Ключ для подписи должен быть байтовым")

    try:
        return hmac.new(
            key, data.encode(DEFAULT_ENCODING), digestmod=HASH_ALGORITHM
        ).digest()
    except Exception as exc:
        raise CryptoError(f"Ошибка подписи данных: {exc}")


def verify_signature(data: str, key: bytes, signature: bytes) -> bool:
    """
    Проверяет корректность HMAC-подписи.
    """
    if (
        not isinstance(data, str)
        or not isinstance(key, (bytes, bytearray))
        or not isinstance(signature, (bytes, bytearray))
    ):
        return False

    try:
        expected = sign_data(data, key)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False
