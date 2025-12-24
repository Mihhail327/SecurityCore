
# SecurityCore 🔐

SecurityCore — это модульная библиотека на Python для анализа, защиты и валидации данных.  
Она создана как набор "артефактов безопасности", которые можно использовать в любых проектах: от веб‑приложений до инфраструктурных сервисов.

---

## ✨ Возможности

- **crypto_utils** — хэширование (SHA256, MD5), генерация ключей и токенов, симметричное шифрование (Fernet).
- **input_sanitizer** — очистка ввода, защита от XSS и SQL‑инъекций.
- **validators** — проверка email, URL, телефонов, паролей и IP‑адресов.
- **password_analyzer** — анализ паролей, определение уровня надёжности и рекомендации.
- **audit_logger** — аудит событий и логирование действий.

---

## 🚀 Установка

```bash
pip install securitycore
```

*(или клонируй репозиторий и установи локально)*

```bash
git clone https://github.com/Mihhail327/SecurityCore.git
cd SecurityCore
pip install -r requirements.txt
```

---

## 🧪 Тестирование

SecurityCore покрыт тестами с использованием **pytest**.  
Запуск тестов:

```bash
pytest -v
```

---

## 📊 Пример использования

```python
from securitycore.crypto import crypto_utils
from securitycore.protection import input_sanitizer
from securitycore.validation import validators

# Хэширование
print(crypto_utils.hash_sha256("mypassword"))

# Очистка ввода
data = "<script>alert('XSS')</script>"
print(input_sanitizer.sanitize_input(data))

# Валидация email
print(validators.is_valid_email("user@example.com"))
```

---

## 📜 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).

---

## 🛡️ Автор

Разработано **Mihhail327** — архитектор систем и создатель SecurityCore.  
Каждый модуль — это артефакт, каждая документация — кодекс.  
SecurityCore — твой набор инструментов для защиты и анализа данных.
```
