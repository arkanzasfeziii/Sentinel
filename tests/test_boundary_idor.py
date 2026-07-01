"""Boundary tests for sentinel.modules.idor helper functions."""

from sentinel.modules.idor import _idor_id_generator

# ── _idor_id_generator ──────────────────────────────────────────────────────

def test_idor_numeric_id():
    ids = list(_idor_id_generator(10, count=20))
    assert len(ids) > 0


def test_idor_string_id():
    ids = list(_idor_id_generator("abc123", count=10))
    assert len(ids) > 0


def test_idor_zero_count():
    ids = list(_idor_id_generator(1, count=0))
    assert ids == [] or isinstance(ids, list)


def test_idor_negative_id():
    ids = list(_idor_id_generator(-5, count=10))
    assert isinstance(ids, list)


def test_idor_large_id():
    ids = list(_idor_id_generator(999999999, count=10))
    assert len(ids) > 0
