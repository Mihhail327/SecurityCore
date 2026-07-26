import time
import jwt

from securitycore._internal.constants import TOKEN_EXPIRATION_SECONDS
from securitycore._internal.error import CryptoError
from securitycore.crypto.keygen import generate_hmac_key


def generate_token(
    payload: dict,
    key: bytes | str,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
    algorithm: str = "HS256",
) -> str:
    """
    Создаёт подписанный токен в формате JWT.
    """
    if not isinstance(payload, dict):
        raise CryptoError("Payload должен быть словарём")

    if key is None:
        raise CryptoError("Ключ подписи 'key' обязателен для генерации JWT токена")

    try:
        jwt_payload = {
            "exp": int(time.time()) + expires_in,
            "data": payload,
        }

        token = jwt.encode(jwt_payload, key, algorithm=algorithm)
        return token
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


def verify_token(
    token: str,
    key: bytes | str,
    algorithms: list[str] | tuple[str, ...] | None = None,
) -> dict:
    """
    Проверяет подпись и срок действия токена (JWT).
    """
    if not isinstance(token, str):
        raise CryptoError("Некорректный формат токена")

    allowed_algorithms = list(algorithms) if algorithms else ["HS256"]

    try:
        decoded = jwt.decode(token, key, algorithms=allowed_algorithms)
        return decoded.get("data", {})
    except jwt.ExpiredSignatureError:
        raise CryptoError("Срок действия токена истёк")
    except jwt.InvalidTokenError as exc:
        raise CryptoError(f"Подпись токена недействительна: {exc}")
    except Exception as exc:
        raise CryptoError(f"Ошибка декодирования структуры токена: {exc}")


def create_token_pair(
    payload: dict,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
    algorithm: str = "HS256",
) -> tuple[str, bytes]:
    """Создаёт токен и возвращает его вместе с ключом."""
    key = generate_hmac_key()
    token = generate_token(payload, key, expires_in, algorithm=algorithm)
    return token, key
