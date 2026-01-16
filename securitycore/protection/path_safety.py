import os
import re

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


# Проверка на path traversal
def ensure_no_path_traversal(path: str) -> None:
    """
    Проверяет, что путь не содержит попыток выхода за пределы директории.
    """
    if not isinstance(path, str):
        raise SecurityViolationError("Путь должен быть строкой")

    if PATH_TRAVERSAL_PATTERN.search(path):
        raise SecurityViolationError("Обнаружена попытка path traversal")

    normalized = os.path.normpath(path)
    if normalized.startswith("..") or normalized.startswith("/.."):
        raise SecurityViolationError("Небезопасный нормализованный путь")


# Проверка имени файла
def ensure_safe_filename(filename: str) -> None:
    """
    Проверяет, что имя файла безопасно:
    - нет запрещённых символов
    - нет запрещённых имён
    - нет запрещённых расширений
    """
    if not isinstance(filename, str):
        raise SecurityViolationError("Имя файла должно быть строкой")

    if len(filename) > MAX_PATH_LENGTH:
        raise SecurityViolationError("Имя файла слишком длинное")

    if INVALID_FILENAME_PATTERN.search(filename):
        raise SecurityViolationError("Имя файла содержит запрещённые символы")

    name_lower = filename.lower()

    if name_lower in FORBIDDEN_FILENAMES:
        raise SecurityViolationError("Имя файла запрещено политикой безопасности")

    _, ext = os.path.splitext(name_lower)
    if ext in FORBIDDEN_EXTENSIONS:
        raise SecurityViolationError("Расширение файла запрещено")


# Проверка полного пути
def ensure_safe_path(path: str) -> None:
    """
    Комплексная проверка пути:
    - отсутствие path traversal
    - безопасное имя файла
    """
    ensure_no_path_traversal(path)

    filename = os.path.basename(path)
    ensure_safe_filename(filename)