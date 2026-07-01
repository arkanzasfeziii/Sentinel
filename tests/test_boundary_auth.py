"""Boundary tests for sentinel.modules.auth helper functions."""

import json

from sentinel.modules.auth import _forge_jwt_hs256, _forge_jwt_none, _random_str
from sentinel.utils.http import b64url_encode


def _make_jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.{sig}"


# ── _random_str ─────────────────────────────────────────────────────────────

def test_random_str_zero():
    assert _random_str(0) == ""


def test_random_str_one():
    assert len(_random_str(1)) == 1


def test_random_str_large():
    assert len(_random_str(10000)) == 10000


def test_random_str_alphanumeric():
    s = _random_str(100)
    assert all(c.isalnum() for c in s)


def test_random_str_uniqueness():
    results = {_random_str(20) for _ in range(50)}
    assert len(results) > 40


# ── _forge_jwt_none ─────────────────────────────────────────────────────────

def test_forge_none_valid():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    result = _forge_jwt_none(token)
    assert isinstance(result, list)
    assert len(result) > 0


def test_forge_none_empty():
    result = _forge_jwt_none("")
    assert result == []


def test_forge_none_invalid():
    result = _forge_jwt_none("not.a.valid.jwt.token")
    assert result == []


def test_forge_none_no_dots():
    result = _forge_jwt_none("garbage")
    assert result == []


def test_forge_none_alg_preserved():
    token = _make_jwt({"alg": "RS256"}, {"admin": True})
    forged = _forge_jwt_none(token)
    for t in forged:
        parts = t.split(".")
        assert len(parts) >= 2


# ── _forge_jwt_hs256 ───────────────────────────────────────────────────────

def test_forge_hs256_valid():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1"})
    result = _forge_jwt_hs256(token, "secret")
    assert isinstance(result, str)
    assert result.count(".") == 2


def test_forge_hs256_empty_secret():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1"})
    result = _forge_jwt_hs256(token, "")
    assert isinstance(result, str)


def test_forge_hs256_long_secret():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1"})
    result = _forge_jwt_hs256(token, "S" * 10000)
    assert isinstance(result, str)


def test_forge_hs256_empty_token():
    result = _forge_jwt_hs256("", "secret")
    assert result == ""


def test_forge_hs256_invalid_token():
    result = _forge_jwt_hs256("invalid", "secret")
    assert isinstance(result, str)
