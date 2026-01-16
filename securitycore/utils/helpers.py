import time
import uuid
from typing import Any, Iterable, List


def utc_timestamp() -> int:
    """Возвращает текущий Unix timestamp в UTC."""
    return int(time.time())


def short_uuid() -> str:
    """Генерирует короткий UUID (8 символов)."""
    return uuid.uuid4().hex[:8]


def chunk_list(items: Iterable[Any], size: int) -> List[List[Any]]:
    """Разбивает последовательность на чанки фиксированного размера."""
    if size <= 0:
        raise ValueError("Chunk size must be positive")

    chunk = []
    result = []

    for item in items:
        chunk.append(item)
        if len(chunk) == size:
            result.append(chunk)
            chunk = []

    if chunk:
        result.append(chunk)

    return result


def flatten(nested: Iterable[Iterable[Any]]) -> List[Any]:
    """Преобразует список списков в один плоский список."""
    return [item for group in nested if group for item in group]


def safe_str(value: Any) -> str:
    """Безопасно преобразует значение в строку."""
    try:
        return str(value)
    except BaseException:
        return "<unrepresentable>"


def is_empty(value: Any) -> bool:
    """Проверяет, является ли значение пустым."""
    if value is None:
        return True

    if isinstance(value, str) and value.strip() == "":
        return True

    if isinstance(value, (list, dict, tuple, set, bytes, bytearray)) and len(value) == 0:
        return True

    return False