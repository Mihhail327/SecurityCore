import time
import jwt

from securitycore._internal.constants import TOKEN_EXPIRATION_SECONDS
from securitycore._internal.error import CryptoError
from securitycore.crypto.keygen import generate_hmac_key


def generate_token(
    payload: dict,
    key: bytes | None = None,
    expires_in: int = TOKEN_EXPIRATION_SECONDS,
) -> str:
    """
    Создаёт подписанный токен в формате JWT.
    """
    if not isinstance(payload, dict):
        raise CryptoError("Payload должен быть словарём")

    # Используем переданный ключ или генерируем новый
    working_key = key if key is not None else generate_hmac_key()

    try:
        # Для обратной совместимости с `data` внутри словаря
        # Стандарт JWT: используем claim `exp` для времени
        jwt_payload = {
            "exp": int(time.time()) + expires_in,
            "data": payload,
        }

        # PyJWT сам закодирует всё в base64url и подпишет
        token = jwt.encode(jwt_payload, working_key, algorithm="HS256")
        return token
    except Exception as exc:
        raise CryptoError(f"Ошибка генерации токена: {exc}")


def verify_token(token: str, key: bytes) -> dict:
    """
    Проверяет подпись и срок действия токена (JWT).
    """
    if not isinstance(token, str):
        raise CryptoError("Некорректный формат токена")

    try:
        # PyJWT сам проверит подпись и время жизни (exp)
        decoded = jwt.decode(token, key, algorithms=["HS256"])
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
) -> tuple[str, bytes]:
    """Создаёт токен и возвращает его вместе с ключом."""
    key = generate_hmac_key()
    token = generate_token(payload, key, expires_in)
    return token, key
