import  hashlib
import secrets
import base64
from cryptography.fernet import Fernet

# Хэширование

def hash_sha256(data: str) -> str:
    """
    Возвращает SHA-256 хэш строки.
    """
    return hashlib.sha256(data.encode()).hexdigest()

def hash_md5(data: str) -> str:
    """
    Возвращает MD5 хэш строки ( не рекомендуется для безопасности, но полезно для проверки целостности).
    """
    return hashlib.md5(data.encode()).hexdigest()

# Генерация ключей и токенов

def generate_secret_key(length: int = 32) -> str:
    """
    Генерирует случайный секретный ключ в hex-формате.
    """
    return secrets.token_hex(length)

def generate_token(length: int = 16) -> str:
    """
    Генерирует случайный токен (base64)
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode()

# Симитричное шифрование (Fernet)

def generate_fernet_key() -> bytes:
    """
    Генерирует ключ для Fernet.
    """
    return Fernet.generate_key()

def encrypt_message(message: str, key: bytes) -> str:
    """
    Шифрует сообщение с использованием Fernet.
    """
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(token: str, key: bytes) -> str:
    """
    Дешифрует сообщение с использованием Fernet.
    """
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()