
---

# 🔐 SecurityCore

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
| **🔑 Crypto** | Продвинутая криптография и анализ | `analyze_password`, `hash_data`, `generate_token` |
| **🛡️ Protection** | Защита от классических атак (OWASP) | `sanitize_xss`, `sanitize_sql_input`, `ensure_safe_path` |
| **✔️ Validation** | Строгая проверка типов и форматов | `validate_email`, `validate_ip`, `validate_url` |
| **📜 Audit** | Протоколирование для SIEM | `audit`, `audit_json` |

---

## 🚀 Быстрый старт

### 1. Установка

```bash
# Установка через pip
pip install securitycore

# Для разработки и контрибьютинга
git clone https://github.com/Mihhail327/SecurityCore.git
cd SecurityCore && poetry install

```

---

### 2. Примеры использования

#### 🧠 Анализ сложности (Энтропия)

> Не просто считает длину, а вычисляет реальную стойкость к брутфорсу.

```python
from securitycore import analyze_password

res = analyze_password("SuperSecret123!")
print(f"📊 Стойкость: {res['strength']} ({res['bits']:.2f} bits)")

```

#### 🧼 Очистка ввода (XSS/SQLi)

```python
from securitycore import input_sanitizer

raw_html = "<img src=x onerror=alert(1)> Привет!"
clean_html = input_sanitizer(raw_html)
# Результат: &lt;img src=x onerror=alert(1)&gt; Привет!

```

#### 🌐 Валидация сетевых данных

```python
from securitycore import validate_ip

ip = validate_ip("2001:db8::1") # Поддержка IPv6 из коробки

```

---

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
