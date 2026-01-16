# Базовое исключение SecurityCore
class SecurityCoreError(Exception):
    """
    Базовое исключение для всех ошибок в библиотеке SecurityCore.
    Позволяет перехватывать любые внутренние ошибки единообразно.
    """
    pass


# Ошибки валидации
class ValidationError(SecurityCoreError):
    """
    Ошибка валидации входных данных.
    Используется валидаторами и санитайзерами.
    """
    pass


# Ошибки безопасности
class SecurityViolationError(SecurityCoreError):
    """
    Ошибка, возникающая при попытке небезопасной операции:
    - path traversal
    - SQL-инъекция
    - XSS
    - небезопасные токены
    """
    pass


# Ошибки криптографии
class CryptoError(SecurityCoreError):
    """
    Ошибка криптографических операций:
    - генерация ключей
    - хэширование
    - подписи
    - токены
    """
    pass


# Ошибки аудита
class AuditError(SecurityCoreError):
    """
    Ошибка логирования или записи аудита.
    """
    pass