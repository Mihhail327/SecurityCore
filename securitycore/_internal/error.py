from typing import Any


class SecurityCoreError(Exception):
    """
    Базовое исключение для всех ошибок в библиотеке SecurityCore.
    """

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.details = details


class ValidationError(SecurityCoreError):
    """
    Ошибка валидации входных данных.
    """

    pass


class SecurityViolationError(SecurityCoreError):
    """
    Ошибка при попытке небезопасной операции.
    """

    pass


class CryptoError(SecurityCoreError):
    """
    Ошибка криптографических операций.
    """

    pass


class AuditError(SecurityCoreError):
    """
    Ошибка логирования или записи аудита.
    """

    pass
