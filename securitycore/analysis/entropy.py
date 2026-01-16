from math import log2
from securitycore._internal.constants import SPECIAL_CHARS


# Энтропия по Шеннону
def entropy(value: str) -> float:
    """
    Возвращает энтропию строки в битах.
    """
    if not value:
        return 0.0

    length = len(value)
    freq = {}

    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1

    h = 0.0
    for count in freq.values():
        p = count / length
        h -= p * log2(p)

    return h


# Общая энтропия (H * длина)
def total_entropy(value: str) -> float:
    """
    Общая энтропия строки: H * длина.
    """
    if not value:
        return 0.0

    return entropy(value) * len(value)



# Размер алфавита
def estimate_charset_size(value: str) -> int:
    """
    Определяет размер алфавита, используемого в строке.
    """
    size = 0

    if any(ch.islower() for ch in value):
        size += 26
    if any(ch.isupper() for ch in value):
        size += 26
    if any(ch.isdigit() for ch in value):
        size += 10
    if any(ch in SPECIAL_CHARS for ch in value):
        size += len(SPECIAL_CHARS)

    return size