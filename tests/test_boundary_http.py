"""Boundary tests for sentinel.utils.http functions."""

import base64
import json

from sentinel.utils.http import b64url_decode, b64url_encode, jwt_parts


# ── b64url_encode ───────────────────────────────────────────────────────────

def test_encode_empty():
    assert b64url_encode(b"") == ""


def test_encode_single_byte():
    result = b64url_encode(b"\x00")
    assert isinstance(result, str)
    assert "=" not in result


def test_encode_binary():
    result = b64url_encode(b"\xff\xfe\xfd\x00\x01")
    assert isinstance(result, str)


def test_encode_large():
    result = b64url_encode(b"A" * 100000)
    assert len(result) > 0


def test_encode_unicode_bytes():
    result = b64url_encode("تست".encode("utf-8"))
    assert isinstance(result, str)


# ── b64url_decode ───────────────────────────────────────────────────────────

def test_decode_empty():
    result = b64url_decode("")
    assert result == b""


def test_decode_roundtrip():
    original = b"hello world test data"
    assert b64url_decode(b64url_encode(original)) == original


def test_decode_no_padding():
    encoded = base64.urlsafe_b64encode(b"test").rstrip(b"=").decode()
    assert b64url_decode(encoded) == b"test"


def test_decode_with_padding():
    assert b64url_decode("dGVzdA==") == b"test"


def test_decode_url_safe_chars():
    data = b"\xfb\xff\xfe"
    encoded = b64url_encode(data)
    assert "+" not in encoded
    assert "/" not in encoded


# ── jwt_parts ───────────────────────────────────────────────────────────────

def _make_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.{sig}"


def test_jwt_valid():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1234"})
    result = jwt_parts(token)
    assert result is not None
    h, p, s = result
    assert h["alg"] == "HS256"
    assert p["sub"] == "1234"


def test_jwt_empty_string():
    assert jwt_parts("") is None


def test_jwt_no_dots():
    assert jwt_parts("nodots") is None


def test_jwt_too_many_dots():
    assert jwt_parts("a.b.c.d.e") is None


def test_jwt_invalid_base64():
    assert jwt_parts("!!!.@@@.###") is None
