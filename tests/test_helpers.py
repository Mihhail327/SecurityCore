import pytest
from securitycore.utils.helpers import (
    utc_timestamp,
    short_uuid,
    chunk_list,
    flatten,
    safe_str,
    is_empty,
)


def test_utc_timestamp():
    ts = utc_timestamp()
    assert isinstance(ts, int)
    assert ts > 1700000000


def test_short_uuid():
    uid = short_uuid()
    assert isinstance(uid, str)
    assert len(uid) == 8


def test_chunk_list():
    items = [1, 2, 3, 4, 5]
    chunks = list(chunk_list(items, 2))
    assert chunks == [[1, 2], [3, 4], [5]]

    with pytest.raises(ValueError):
        list(chunk_list(items, 0))


def test_flatten():
    nested = [[1, 2], [3, 4], [5]]
    flat = flatten(nested)
    assert flat == [1, 2, 3, 4, 5]


def test_safe_str():
    assert safe_str("hello") == "hello"
    long_str = "a" * 2000
    res = safe_str(long_str, max_len=10)
    assert res == "aaaaaaaaaa..."
    assert safe_str("null\x00byte") == "nullbyte"


def test_is_empty():
    assert is_empty(None) is True
    assert is_empty("") is True
    assert is_empty("   ") is True
    assert is_empty([]) is True
    assert is_empty({}) is True
    assert is_empty("text") is False
    assert is_empty([1]) is False
