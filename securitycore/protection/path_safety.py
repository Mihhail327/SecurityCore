import os

from securitycore._internal.error import SecurityViolationError
from securitycore._internal.constants import (
    MAX_PATH_LENGTH,
    FORBIDDEN_FILENAMES,
    FORBIDDEN_EXTENSIONS,
)
from securitycore._internal.regexes import (
    PATH_TRAVERSAL_PATTERN,
    INVALID_FILENAME_PATTERN,
)


def ensure_no_path_traversal(path: str) -> None:
    """Проверяет путь на попытки выхода за пределы (Directory Traversal)."""
    if not isinstance(path, str):
        raise SecurityViolationError("Путь должен быть строкой")

    # 1. Защита от Null-byte (критично для файловых операций)
    if "\x00" in path:
        raise SecurityViolationError("Обнаружен запрещенный null-byte")

    # 2. Регулярка для быстрого отлова паттернов типа %2e%2e
    if PATH_TRAVERSAL_PATTERN.search(path):
        raise SecurityViolationError("Обнаружена попытка path traversal")

    # 3. Глубокая нормализация
    normalized = os.path.normpath(path)

    # Запрещаем выход вверх и абсолютные пути (для безопасности)
    if normalized.startswith("..") or os.path.isabs(normalized):
        raise SecurityViolationError(f"Небезопасный путь: {normalized}")


def ensure_safe_filename(filename: str) -> None:
    """Проверяет безопасность имени файла."""
    if not isinstance(filename, str):
        raise SecurityViolationError("Имя файла должно быть строкой")

    if not filename or len(filename) > MAX_PATH_LENGTH:
        raise SecurityViolationError("Некорректная длина имени файла")

    # Проверка на запрещенные символы (Windows/Linux)
    if INVALID_FILENAME_PATTERN.search(filename):
        raise SecurityViolationError("Имя файла содержит запрещённые символы")

    name_lower = filename.lower().strip()

    # Проверка системных имен (CON, PRN, NUL и т.д.)
    pure_name = os.path.splitext(name_lower)[0]
    if pure_name in FORBIDDEN_FILENAMES or name_lower in FORBIDDEN_FILENAMES:
        raise SecurityViolationError("Имя файла зарезервировано системой")

    _, ext = os.path.splitext(name_lower)
    if ext in FORBIDDEN_EXTENSIONS:
        raise SecurityViolationError(f"Расширение {ext} запрещено")


def ensure_safe_path(path: str) -> None:
    """Комплексная проверка безопасности пути."""
    ensure_no_path_traversal(path)

    filename = os.path.basename(path)
    if filename:  # Если путь не заканчивается на слэш
        ensure_safe_filename(filename)
