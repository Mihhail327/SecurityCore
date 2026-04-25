import hashlib
import secrets

from securitycore._internal.constants import (
    DEFAULT_ENCODING,
    DEFAULT_TOKEN_LENGTH,
    HASH_ITERATIONS,
)
from securitycore._internal.error import CryptoError


def generate_bytes_key(length: int = DEFAULT_TOKEN_LENGTH) -> bytes:
    """Генерирует криптографически стойкий байтовый ключ."""
    if length <= 0:
        raise CryptoError("Длина ключа должна быть положительным числом")
    return secrets.token_bytes(length)


def generate_hex_key(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """Генерирует криптографически стойкий ключ в hex-формате."""
    if length <= 0:
        raise CryptoError("Длина hex-ключа должна быть положительной")
    return secrets.token_hex(length)


def derive_key_from_password(
    password: str, salt: bytes, iterations: int = HASH_ITERATIONS, dklen: int = 32
) -> bytes:
    """
    Генерирует ключ из пароля через PBKDF2-HMAC-SHA256.
    dklen: желаемая длина ключа (по умолчанию 32 байта для AES-256).
    """
    if not isinstance(password, str):
        raise CryptoError("Пароль должен быть строкой")
    if not isinstance(salt, (bytes, bytearray)):
        raise CryptoError("Соль должна быть байтовой")
    if iterations <= 0:
        raise CryptoError("Количество итераций должно быть положительным")

    try:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode(DEFAULT_ENCODING), salt, iterations, dklen
        )
    except Exception as exc:
        raise CryptoError(f"Ошибка деривации ключа: {exc}")


def generate_hmac_key(length: int = DEFAULT_TOKEN_LENGTH) -> bytes:
    """Генерирует ключ для HMAC-подписи."""
    # Senior Tip: Просто вызываем базовую функцию, не плодим лишние try-except
    return generate_bytes_key(length)


def generate_api_key(length: int = 32, prefix: str = "sec_live_") -> str:
    """
    Генерирует человекочитаемый API-ключ.
    length: количество байт энтропии (итоговая строка будет в 2 раза длиннее).
    prefix: префикс для ключа (например, sec_live_ для продакшена).
    """
    try:
        # Генерируем ключ и добавляем префикс
        key_body = generate_hex_key(length)
        return f"{prefix}{key_body}"
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации API-ключа: {exc}")
