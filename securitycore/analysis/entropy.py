from math import log2
from collections import Counter
from securitycore._internal.constants import SPECIAL_CHARS


def entropy(value: str) -> float:
    """
    Возвращает энтропию Шеннона в битах на символ.
    Показывает степень непредсказуемости данных.
    """
    if not value:
        return 0.0

    length = len(value)
    # Используем Counter для ускорения подсчета частот
    counts = Counter(value)

    h = 0.0
    for count in counts.values():
        p = count / length
        h -= p * log2(p)

    return h


def total_entropy(value: str) -> float:
    """
    Информационная емкость строки (H * length).
    """
    return entropy(value) * len(value)


def estimate_charset_size(value: str) -> int:
    """
    Определяет размер алфавита через маппинг правил.
    """
    if not value:
        return 0

    # Определяем наличие категорий за один проход
    found_categories = {
        "lower": False,
        "upper": False,
        "digit": False,
        "special": False,
    }

    special_set = set(SPECIAL_CHARS)

    for ch in value:
        if ch.islower():
            found_categories["lower"] = True
        elif ch.isupper():
            found_categories["upper"] = True
        elif ch.isdigit():
            found_categories["digit"] = True
        elif ch in special_set:
            found_categories["special"] = True

        # Оптимизация: если всё нашли, можно выходить из цикла раньше
        if all(found_categories.values()):
            break

    # Маппинг весов категорий
    weights = {"lower": 26, "upper": 26, "digit": 10, "special": len(SPECIAL_CHARS)}

    # Считаем итоговый размер через генератор
    size = sum(weights[cat] for cat, found in found_categories.items() if found)

    return size if size > 0 else len(set(value))


def brute_force_resistance(value: str) -> float:
    """
    Senior Feature: Оценка стойкости к брутфорсу в битах.
    Формула: log2(charset_size ^ length)
    """
    if not value:
        return 0.0

    size = estimate_charset_size(value)
    if size <= 1:
        return 0.0

    return len(value) * log2(size)
