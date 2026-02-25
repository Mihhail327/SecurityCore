import time
import json

from securitycore._internal.constants import (
    DEFAULT_ENCODING,
    TOKEN_EXPIRATION_SECONDS,
)
from securitycore._internal.error import CryptoError
from securitycore.crypto.crypto_utils import sign_data, verify_signature
from securitycore.crypto.keygen import generate_hmac_key


def generate_token(
    payload: dict,
    key: bytes | None = None,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
) -> str:
    """
    Создаёт подписанный токен.
    Формат: HEX_DATA.HEX_SIGNATURE
    """
    if not isinstance(payload, dict):
        raise CryptoError("Payload должен быть словарём")

    # Используем переданный ключ или генерируем новый (но тогда его надо вернуть!)
    # Senior Note: В продакшене ключ обычно достается из конфига
    working_key = key if key is not None else generate_hmac_key()

    try:
        data = {
            "exp": int(time.time()) + expires_in,
            "data": payload,
        }

        # Делаем JSON максимально компактным (без пробелов)
        raw_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))

        signature = sign_data(raw_json, working_key)

        # Кодируем данные в hex для безопасной передачи в URL/Headers
        return raw_json.encode(DEFAULT_ENCODING).hex() + "." + signature.hex()

    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


def verify_token(token: str, key: bytes) -> dict:
    """
    Проверяет подпись и срок действия токена.
    """
    if not isinstance(token, str) or "." not in token:
        raise CryptoError("Некорректный формат токена")

    try:
        raw_hex, sig_hex = token.split(".", 1)
        raw_json = bytes.fromhex(raw_hex).decode(DEFAULT_ENCODING)
        signature = bytes.fromhex(sig_hex)
    except Exception:
        raise CryptoError("Ошибка декодирования структуры токена")

    # 1. Сначала проверка подписи (Critical Path)
    if not verify_signature(raw_json, key, signature):
        raise CryptoError("Подпись токена недействительна")

    # 2. Только после валидной подписи парсим JSON
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        raise CryptoError("Повреждённый контент токена")

    # 3. Проверка времени
    exp = data.get("exp")
    if not isinstance(exp, (int, float)) or time.time() > exp:
        raise CryptoError("Срок действия токена истёк")

    return data.get("data", {})


def create_token_pair(
    payload: dict,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
) -> tuple[str, bytes]:
    """Создаёт токен и возвращает его вместе с ключом."""
    key = generate_hmac_key()
    token = generate_token(payload, key, expires_in)
    return token, key
