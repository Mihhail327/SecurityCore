
---

# 🔐 SecurityCore

*Read this in [English](#english-version) | Читать на [Русском](#-securitycore)*

<p align="center">
<img src="https://img.shields.io/badge/Python-3.13+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
<img src="https://img.shields.io/badge/Poetry-Project-6366f1?style=for-the-badge&logo=poetry&logoColor=white" alt="Poetry">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

**SecurityCore** — это швейцарский нож для обеспечения безопасности ваших данных. Объединил продвинутый анализ энтропии, многоуровневую защиту от инъекций и строгую валидацию в один лаконичный SDK.

---

## 🛠 Ключевые возможности

| Модуль | Описание | Основные функции |
| --- | --- | --- |
| **🔑 Crypto** | Продвинутая криптография (Argon2, JWT) | `hash_password`, `verify_password`, `create_token_pair` |
| **🛡️ Protection** | Защита от классических атак (IDS, nh3 XSS) | `sanitize_xss`, `ensure_no_sql_injection`, `SafeString` |
| **✔️ Validation** | Строгая проверка типов и форматов | `validate_email`, `validate_ip`, `validate_url` |
| **📜 Audit** | Протоколирование для SIEM | `audit`, `audit_json` |
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
print(f"📊 Стойкость: {res['strength']} ({res['bits']:.2f} bits)")

```

#### 🧼 Очистка ввода (XSS/SQLi)

```python
from securitycore import input_sanitizer

raw_html = "<img src=x onerror=alert(1)> Привет!"
clean_html = input_sanitizer(raw_html)
# Результат: &lt;img src=x onerror=alert(1)&gt; Привет!

```

#### 🔑 Хеширование паролей (Argon2)

```python
from securitycore import hash_password, verify_password

# Автоматически использует надежные настройки памяти и времени
pwhash = hash_password("SuperSecret123!")
is_valid = verify_password("SuperSecret123!", pwhash)
```

#### 🛡️ FastAPI Интеграция (IDS и Security Headers)

```python
from fastapi import FastAPI
from securitycore.integrations import SecurityAuditMiddleware

app = FastAPI()
# Автоматически логирует XSS/SQLi атаки и добавляет заголовки безопасности
app.add_middleware(SecurityAuditMiddleware)
```

---

## 🔄 Миграция (с v1.0 на v1.1+)

В новой версии мы перешли на **Argon2** и **JWT**.

**Токены:** Ранее `generate_token` возвращал кастомный HEX-формат. Теперь он использует индустриальный стандарт **JWT** (`PyJWT`).
Если вы используете токены, вам не нужно менять код вызова `generate_token(payload, key)`, но учтите, что формат изменился на `ey...`.

**Хеширование:** Для новых паролей используйте `hash_password`. Старая функция `hash_data` (PBKDF2) оставлена для обратной совместимости, но помечена как Legacy.

## 🧪 Надежность и Тестирование

Придерживаюсь подхода **Test-Driven Development**. Стабильность гарантирована полным покрытием `pytest`.

```bash
poetry run pytest -v

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
| **🔑 Crypto** | Advanced cryptography (Argon2, JWT) | `hash_password`, `verify_password`, `create_token_pair` |
| **🛡️ Protection** | Classic attack prevention (IDS, nh3 XSS) | `sanitize_xss`, `ensure_no_sql_injection`, `SafeString` |
| **✔️ Validation** | Strict type and format validation | `validate_email`, `validate_ip`, `validate_url` |
| **📜 Audit** | SIEM-ready logging | `audit`, `audit_json` |
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
print(f"📊 Strength: {res['strength']} ({res['bits']:.2f} bits)")
```

#### 🧼 Input Sanitization (XSS/SQLi)

```python
from securitycore import input_sanitizer

raw_html = "<img src=x onerror=alert(1)> Hello!"
clean_html = input_sanitizer(raw_html)
# Result: &lt;img src=x onerror=alert(1)&gt; Hello!
```

#### 🔑 Password Hashing (Argon2)

```python
from securitycore import hash_password, verify_password

# Automatically uses secure memory and time cost settings
pwhash = hash_password("SuperSecret123!")
is_valid = verify_password("SuperSecret123!", pwhash)
```

#### 🛡️ FastAPI Integration (IDS & Security Headers)

```python
from fastapi import FastAPI
from securitycore.integrations import SecurityAuditMiddleware

app = FastAPI()
# Automatically logs XSS/SQLi attacks and adds security headers
app.add_middleware(SecurityAuditMiddleware)
```

---

## 🔄 Migration (from v1.0 to v1.1+)

In the new version, we migrated to **Argon2** and **JWT**.

**Tokens:** Previously, `generate_token` returned a custom HEX format. Now it uses the industry standard **JWT** (`PyJWT`). If you use tokens, you don't need to change the `generate_token(payload, key)` call code, but be aware that the format has changed to `ey...`.

**Hashing:** For new passwords, use `hash_password`. The old `hash_data` (PBKDF2) function is kept for backward compatibility but marked as Legacy.

## 🧪 Reliability and Testing

I follow the **Test-Driven Development** approach. Stability is guaranteed by full `pytest` coverage.

```bash
poetry run pytest -v
```

---

## 👨‍💻 About the Author

The project is maintained by **Mihhail327**.

The **SecurityCore** library grew out of a personal interest in information security and a desire to create tools that make code cleaner and more secure.

---

## 📜 License

Distributed under the **MIT** license. See the `LICENSE` file for details.

---
