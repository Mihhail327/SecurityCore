import uuid
from itertools import chain, islice
from datetime import datetime, timezone
from typing import Any, Iterable, List, Generator


def utc_timestamp() -> int:
    """Возвращает текущий Unix timestamp (UTC)."""
    # Python 3.13 standard way
    return int(datetime.now(timezone.utc).timestamp())


def short_uuid() -> str:
    """Генерирует короткий UUID (8 символов)."""
    return uuid.uuid4().hex[:8]


def chunk_list(items: Iterable[Any], size: int) -> Generator[List[Any], None, None]:
    """
    Разбивает последовательность на чанки (генератор).
    Экономно расходует память.
    """
    if size <= 0:
        raise ValueError("Размер чанка должен быть положительным")

    it = iter(items)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


def flatten(nested: Iterable[Iterable[Any]]) -> List[Any]:
    """Преобразует вложенные списки в один плоский."""
    # Используем высокопроизводительный itertools.chain
    return list(chain.from_iterable(nested))


def safe_str(value: Any, max_len: int = 1000) -> str:
    """
    Безопасно преобразует значение в строку с обрезкой.
    Защищает логи от переполнения.
    """
    try:
        s = str(value).replace("\x00", "")
        return (s[:max_len] + "...") if len(s) > max_len else s
    except Exception:
        return "<unrepresentable>"


def is_empty(value: Any) -> bool:
    """Проверяет, является ли значение пустым (None, пустая строка/коллекция)."""
    if value is None:
        return True

    # Строки с пробелами тоже считаем пустыми
    if isinstance(value, str):
        return not value.strip()

    # Проверка коллекций
    try:
        return len(value) == 0
    except (TypeError, AttributeError):
        return False
