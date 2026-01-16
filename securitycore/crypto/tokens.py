import time
import json

from securitycore._internal.constants import (
    DEFAULT_ENCODING,
    TOKEN_EXPIRATION_SECONDS,
)
from securitycore._internal.error import CryptoError
from securitycore.crypto.crypto_utils import sign_data, verify_signature
from securitycore.crypto.keygen import generate_hmac_key


# Генерация подписанного токена
def generate_token(
    payload: dict,
    key: bytes | None = None,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
) -> str:
    """
    Создаёт подписанный токен с полезной нагрузкой и временем истечения.
    Формат:
        hex(json({"exp": ..., "data": ...})) + "." + hex(signature)
    """
    if not isinstance(payload, dict):
        raise CryptoError("Payload должен быть словарём")

    if not isinstance(expires_in, int) or expires_in <= 0:
        raise CryptoError("expires_in должен быть положительным числом")

    key = key or generate_hmac_key()

    try:
        data = {
            "exp": int(time.time()) + expires_in,
            "data": payload,
        }

        raw_json = json.dumps(data, ensure_ascii=False)
        raw_bytes = raw_json.encode(DEFAULT_ENCODING)

        signature = sign_data(raw_json, key)

        return raw_bytes.hex() + "." + signature.hex()

    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


# Проверка токена
def verify_token(token: str, key: bytes) -> dict:
    """
    Проверяет подпись и срок действия токена.
    Возвращает payload при успехе.
    """
    if not isinstance(token, str) or "." not in token:
        raise CryptoError("Некорректный формат токена")

    try:
        raw_hex, sig_hex = token.split(".", 1)
    except ValueError:
        raise CryptoError("Некорректный формат токена")

    try:
        raw_bytes = bytes.fromhex(raw_hex)
        signature = bytes.fromhex(sig_hex)
    except Exception:
        raise CryptoError("Некорректная hex-структура токена")

    raw_json = raw_bytes.decode(DEFAULT_ENCODING)

    # Проверка подписи
    if not verify_signature(raw_json, key, signature):
        raise CryptoError("Подпись токена недействительна")

    # Проверка срока действия
    try:
        data = json.loads(raw_json)
    except Exception:
        raise CryptoError("Некорректный JSON внутри токена")

    exp = data.get("exp")
    if not isinstance(exp, int):
        raise CryptoError("Поле exp отсутствует или некорректно")

    if time.time() > exp:
        raise CryptoError("Срок действия токена истёк")

    return data.get("data", {})


# Утилита: создание пары (token, key)
def create_token_pair(
    payload: dict,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
) -> tuple[str, bytes]:
    """
    Создаёт токен и ключ, который нужно хранить на сервере.
    Удобно для одноразовых токенов подтверждения.
    """
    key = generate_hmac_key()
    token = generate_token(payload, key, expires_in)
    return token, key