import secrets
import hashlib

from securitycore._internal.constants import (
    DEFAULT_ENCODING,
    DEFAULT_SALT_LENGTH,
    DEFAULT_TOKEN_LENGTH,
    HASH_ITERATIONS,
)
from securitycore._internal.error import CryptoError


# Генерация случайного байтового ключа
def generate_bytes_key(length: int = DEFAULT_TOKEN_LENGTH) -> bytes:
    """
    Возвращает криптографически стойкий ключ в виде байтов.
    Подходит для:
    - HMAC
    - токенов
    - сессионных ключей
    - симметричных операций
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина ключа должна быть положительным числом")

    try:
        return secrets.token_bytes(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации байтового ключа: {exc}")


# Генерация ключа в hex-формате
def generate_hex_key(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """
    Возвращает криптографически стойкий ключ в hex-формате.
    Удобен для хранения в переменных окружения и конфигурациях.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина hex-ключа должна быть положительной")

    try:
        return secrets.token_hex(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации hex-ключа: {exc}")


# Генерация ключа на основе пароля (PBKDF2)
def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = HASH_ITERATIONS,
) -> bytes:
    """
    Генерирует ключ из пароля с использованием PBKDF2-HMAC-SHA256.
    Подходит для:
    - шифрования
    - подписи
    - хранения секретов
    """
    if not isinstance(password, str):
        raise CryptoError("Пароль должен быть строкой")

    if not isinstance(salt, (bytes, bytearray)):
        raise CryptoError("Соль должна быть байтовой")

    if not isinstance(iterations, int) or iterations <= 0:
        raise CryptoError("Количество итераций должно быть положительным числом")

    try:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(DEFAULT_ENCODING),
            salt,
            iterations,
        )
    except Exception as exc:
        raise CryptoError(f"Ошибка derivation-ключа: {exc}")


# Генерация HMAC-ключа
def generate_hmac_key(length: int = DEFAULT_TOKEN_LENGTH) -> bytes:
    """
    Генерирует ключ, подходящий для HMAC-подписи.
    """
    try:
        return generate_bytes_key(length)
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации HMAC-ключа: {exc}")


# Генерация API-ключа (человекочитаемый)
def generate_api_key(length: int = 40) -> str:
    """
    Генерирует человекочитаемый API-ключ.
    Формат: HEX (верхний регистр), без спецсимволов.
    """
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("Длина API-ключа должна быть положительной")

    try:
        raw = secrets.token_bytes(length)
        return raw.hex().upper()
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации API-ключа: {exc}")