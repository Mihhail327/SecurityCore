import pytest
from securitycore.crypto import crypto_utils

# Тесты хэширования

def test_hash_sha256():
    result = crypto_utils.hash_sha256("test")
    assert isinstance(result, str)
    assert len(result) == 64 # SHA256 всегда 64 символа

def test_hash_md5():
    result = crypto_utils.hash_md5("test")
    assert isinstance(result, str)
    assert len(result) == 32 # MD5 всегда 32 символа


# Тесты генерации ключей и токенов

def test_generate_secret_key():
    key = crypto_utils.generate_secret_key(16)
    assert isinstance(key, str)
    assert len(key) == 32 # hex-строка длиной 2*length

def test_generate_token():
    token = crypto_utils.generate_token(16)
    assert isinstance(token, str)
    # base64 строка, должна быть не пустой

    assert len(token) > 0


# Тесты шифрования и дешифрования

def test_encrypt_decrypt_message():
    key = crypto_utils.generate_fernet_key()
    message = "Hello SecurityCore!"
    encrypted = crypto_utils.encrypt_message(message, key)
    decrypted = crypto_utils.decrypt_message(encrypted, key)

    assert isinstance(encrypted, str)
    assert decrypted == message

def test_decrypt_invalid_token():
    key = crypto_utils.generate_fernet_key()
    with pytest.raises(Exception):
        crypto_utils.decrypt_message("invalidtoken", key)