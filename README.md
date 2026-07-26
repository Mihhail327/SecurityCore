
# 🔐 SecurityCore

*Read this in [English](#english-version) | Читать на [Русском](#-securitycore)*

<p align="center">
<img src="https://img.shields.io/badge/Python-3.13+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
<img src="https://img.shields.io/badge/Poetry-Project-6366f1?style=for-the-badge&logo=poetry&logoColor=white" alt="Poetry">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

---

**SecurityCore** — это швейцарский нож для обеспечения безопасности ваших данных. Объединил продвинутый анализ энтропии, многоуровневую защиту от инъекций и строгую валидацию в один лаконичный SDK.

---

## 🛠 Ключевые возможности

| Модуль | Описание | Основные функции |
| --- | --- | --- |
| **🔑 Crypto** | Продвинутая криптография (Argon2id, JWT, HMAC) | `hash_password`, `verify_password`, `Argon2Config`, `create_token_pair` |
| **🛡️ Protection** | Защита от классических атак (WAF/IDS, nh3 XSS) | `sanitize_xss`, `ensure_no_xss`, `ensure_no_sql_injection`, `SafeString` |
| **✔️ Validation** | Строгая проверка типов и форматов | `validate_email`, `validate_ip`, `validate_url`, `validate_password` |
| **📜 Audit** | Протоколирование для SIEM с авто-усечением | `audit`, `audit_json` |
| **🔌 Integrations** | Готовые Middleware для фреймворков | `SecurityAuditMiddleware` (FastAPI) |

---

## 🚀 Быстрый старт

### 1. Установка

```bash
# Установка через pip
pip install securitycore

# Для работы с FastAPI добавьте extras
pip install securitycore[fastapi]

# Для разработки и контрибьютинга
git clone https://github.com/Mihhail327/SecurityCore.git
cd SecurityCore && poetry install
```

---

### 2. Примеры использования

#### 🧠 Анализ сложности (Энтропия)

> Не просто считает длину, а вычисляет реальную стойкость к брутфорсу.

```python
from securitycore import password_analyzer

res = password_analyzer("SuperSecret123!")
print(f"📊 Стойкость: {res['strength']} ({res['brute_force_bits']:.2f} bits)")
```

#### 🧼 Очистка ввода (XSS)

```python
from securitycore import input_sanitizer, sanitize_xss

raw_html = "<img src=x onerror=alert(1)> Привет!"
clean_html = sanitize_xss(raw_html)
# Результат: &lt;img src=x onerror=alert(1)&gt; Привет!
```

#### 🔑 Хеширование паролей (Argon2id)

```python
from securitycore import hash_password, verify_password, Argon2Config

# Безопасные настройки по умолчанию
pwhash = hash_password("SuperSecret123!")
is_valid = verify_password("SuperSecret123!", pwhash)

# Кастомная конфигурация памяти и итераций (опционально)
custom_config = Argon2Config(time_cost=2, memory_cost=32768, parallelism=2)
custom_hash = hash_password("SuperSecret123!", config=custom_config)
```

#### 🎫 Генерация и проверка токенов (JWT)

```python
from securitycore import create_token_pair, verify_token

# Создание пары токен + ключ
token, key = create_token_pair({"user_id": 42}, expires_in=3600)

# Валидация токена
payload = verify_token(token, key)
print(payload["user_id"])  # 42
```

#### 🛡️ FastAPI Интеграция (IDS и Security Headers)

```python
from fastapi import FastAPI
from securitycore.integrations import SecurityAuditMiddleware

app = FastAPI()

# Автоматически логирует XSS/SQLi атаки в query-параметрах и добавляет заголовки безопасности
app.add_middleware(SecurityAuditMiddleware)
```

---

## 🔄 Миграция и Изменения в v1.2+

- **JWT Токены**: В `generate_token(payload, key)` параметр `key` теперь является **обязательным**. Для автоматической генерации ключа вместе с токеном используйте `create_token_pair(payload)`.
- **Argon2Config**: Добавлена поддержка передачи кастомного конфига `Argon2Config(time_cost=..., memory_cost=...)` в `hash_password` и `verify_password`.
- **SQL Sanitization**: Функция `sanitize_sql_input` помечена как `Deprecated`. Динамическое удаление символов из SQL-строк не гарантирует безопасность. Для выполнения запросов используйте параметризованные запросы / ORM, а для аудит-мониторинга атак — `ensure_no_sql_injection`.
- **Безопасность аудита**: Аудит-логгеры `audit` и `audit_json` автоматически и безопасно усекают длинные записи (`[TRUNCATED]`) вместо выбрасывания необработанных исключений.

---

## 🧪 Надежность и Тестирование

Библиотека покрыта комплексным набором модульных и интеграционных тестов `pytest`.

```bash
poetry run pytest -v
poetry run ruff check
```

---

## 👨‍💻 Об авторе

Проект поддерживается **Mihhail327**.

Библиотека **SecurityCore** выросла из личного интереса к теме информационной безопасности и стремления создавать инструменты, которые делают код чище и защищеннее.

---

## 📜 Лицензия

Распространяется под лицензией **MIT**. Подробности в файле `LICENSE`.

---

<br><br>

<a name="english-version"></a>
# 🔐 SecurityCore (English Version)

<p align="center">
<img src="https://img.shields.io/badge/Python-3.13+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
<img src="https://img.shields.io/badge/Poetry-Project-6366f1?style=for-the-badge&logo=poetry&logoColor=white" alt="Poetry">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

**SecurityCore** is a Swiss Army knife for securing your data. It combines advanced entropy analysis, multi-layered injection protection, and strict validation into one concise SDK.

---

## 🛠 Key Features

| Module | Description | Core Functions |
| --- | --- | --- |
| **🔑 Crypto** | Advanced cryptography (Argon2id, JWT, HMAC) | `hash_password`, `verify_password`, `Argon2Config`, `create_token_pair` |
| **🛡️ Protection** | Classic attack prevention (WAF/IDS, nh3 XSS) | `sanitize_xss`, `ensure_no_xss`, `ensure_no_sql_injection`, `SafeString` |
| **✔️ Validation** | Strict type and format validation | `validate_email`, `validate_ip`, `validate_url`, `validate_password` |
| **📜 Audit** | SIEM-ready logging with auto-truncation | `audit`, `audit_json` |
| **🔌 Integrations** | Ready-to-use framework middleware | `SecurityAuditMiddleware` (FastAPI) |

---

## 🚀 Quick Start

### 1. Installation

```bash
# Install via pip
pip install securitycore

# For FastAPI integration, add the extras
pip install securitycore[fastapi]

# For development and contributing
git clone https://github.com/Mihhail327/SecurityCore.git
cd SecurityCore && poetry install
```

---

### 2. Usage Examples

#### 🧠 Complexity Analysis (Entropy)

> It doesn't just count the length; it calculates the real resistance against brute-force attacks.

```python
from securitycore import password_analyzer

res = password_analyzer("SuperSecret123!")
print(f"📊 Strength: {res['strength']} ({res['brute_force_bits']:.2f} bits)")
```

#### 🧼 Input Sanitization (XSS)

```python
from securitycore import input_sanitizer, sanitize_xss

raw_html = "<img src=x onerror=alert(1)> Hello!"
clean_html = sanitize_xss(raw_html)
# Result: &lt;img src=x onerror=alert(1)&gt; Hello!
```

#### 🔑 Password Hashing (Argon2id)

```python
from securitycore import hash_password, verify_password, Argon2Config

# Secure defaults out of the box
pwhash = hash_password("SuperSecret123!")
is_valid = verify_password("SuperSecret123!", pwhash)

# Custom memory and cost configuration (optional)
custom_config = Argon2Config(time_cost=2, memory_cost=32768, parallelism=2)
custom_hash = hash_password("SuperSecret123!", config=custom_config)
```

#### 🎫 Token Generation & Verification (JWT)

```python
from securitycore import create_token_pair, verify_token

# Generate token & signing key pair
token, key = create_token_pair({"user_id": 42}, expires_in=3600)

# Verify token
payload = verify_token(token, key)
print(payload["user_id"])  # 42
```

#### 🛡️ FastAPI Integration (IDS & Security Headers)

```python
from fastapi import FastAPI
from securitycore.integrations import SecurityAuditMiddleware

app = FastAPI()

# Automatically logs XSS/SQLi attacks in query params & sets security headers
app.add_middleware(SecurityAuditMiddleware)
```

---

## 🔄 Migration & Changes in v1.2+

- **JWT Tokens**: In `generate_token(payload, key)`, the `key` parameter is now **required**. To generate a token and key pair together, use `create_token_pair(payload)`.
- **Argon2Config**: Added support for passing custom `Argon2Config(time_cost=..., memory_cost=...)` to `hash_password` and `verify_password`.
- **SQL Sanitization**: `sanitize_sql_input` is marked as `Deprecated`. Manual string replacement does not guarantee SQL injection protection. Use ORM / Parameterized queries for SQL operations, and `ensure_no_sql_injection` for WAF/IDS auditing.
- **Audit Resilience**: Audit loggers `audit` and `audit_json` safely truncate oversized log entries (`[TRUNCATED]`) instead of throwing uncaught exceptions.

---

## 🧪 Reliability and Testing

Full test suite with `pytest` and code formatting via `ruff`.

```bash
poetry run pytest -v
poetry run ruff check
```

---

## 👨‍💻 About the Author

The project is maintained by **Mihhail327**.

The **SecurityCore** library grew out of a personal interest in information security and a desire to create tools that make code cleaner and more secure.

---

## 📜 License

Distributed under the **MIT** license. See the `LICENSE` file for details.
