
---

# 🔐 SecurityCore

**SecurityCore** — модульная библиотека Python для анализа, защиты, валидации и безопасной обработки данных.  
Каждый модуль — это самостоятельный «артефакт безопасности», который можно использовать в веб‑приложениях, API‑сервисах, CLI‑утилитах и инфраструктурных системах.

Библиотека построена по принципам:

- строгой валидации  
- безопасных дефолтов  
- отсутствия циклических зависимостей  
- чистой архитектуры  
- предсказуемого API  

---

## ✨ Возможности

### 🔑 Криптография
- PBKDF2‑HMAC хеширование (`hash_data`, `verify_hash`)
- генерация криптографических ключей (`generate_bytes_key`, `generate_hex_key`, `generate_hmac_key`)
- подпись и проверка данных (`sign_data`, `verify_signature`)
- токены с подписью (`generate_token`, `verify_token`, `create_token_pair`)
- анализ энтропии (`entropy`, `total_entropy`, `estimate_charset_size`)

### 🛡️ Защита
- защита от XSS (`sanitize_xss`, `ensure_no_xss`)
- защита от SQL‑инъекций (`sanitize_sql_input`, `ensure_no_sql_injection`)
- безопасная работа с путями (`ensure_safe_path`, `ensure_safe_filename`)

### ✔️ Валидация
- email  
- URL  
- IPv4 / IPv6  
- пароли  
- строки, длины, форматы  

### 📜 Аудит
- текстовый аудит (`audit`)
- JSON‑аудит (`audit_json`)
- безопасная сериализация и структурированные записи

---

## 📦 Установка

```bash
pip install securitycore
```

Или локально:

```bash
git clone https://github.com/mihhail327/SecurityCore.git
cd SecurityCore
pip install -r requirements.txt
```

---

## 📁 Структура библиотеки

```
securitycore/
    crypto/
    protection/
    validators/
    analysis/
    audit/
    utils/
    _internal/
```

---

## 📊 Примеры использования

### Хеширование

```python
from securitycore import hash_data, verify_hash

salt, hashed = hash_data("mypassword")
print(verify_hash("mypassword", salt, hashed))
```

### Токены

```python
from securitycore import generate_token, verify_token, generate_hmac_key

key = generate_hmac_key()
token = generate_token({"user_id": 42}, key)

print(verify_token(token, key))
```

### Защита от XSS

```python
from securitycore import sanitize_xss

print(sanitize_xss("<script>alert('XSS')</script>"))
```

### Валидация email

```python
from securitycore import validate_email

validate_email("user@example.com")
```

### Аудит

```python
from securitycore import audit

audit("user_login", {"user": "alice"})
```

### Энтропия

```python
from securitycore import entropy, total_entropy

print(entropy("MyP@ssw0rd"))
```

---

## 🧪 Тестирование

```bash
pytest -v
```

---

## 📜 Лицензия

MIT License — см. файл `LICENSE`.

---

## 🛡️ Автор

Разработано **Mihhail327**.  
SecurityCore вырос из простого интереса к безопасности и желания разобраться в теме на практике.

---
