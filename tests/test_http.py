"""Tests for HTTP utilities."""

from sentinel.utils.http import b64url_decode, b64url_encode, jwt_parts


def test_b64url_roundtrip():
    data = b"hello world"
    encoded = b64url_encode(data)
    decoded = b64url_decode(encoded)
    assert decoded == data


def test_b64url_no_padding():
    encoded = b64url_encode(b"test")
    assert "=" not in encoded


def test_jwt_parts_valid():
    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
    token = f"{header}.{payload}.signature"
    result = jwt_parts(token)
    assert result is not None
    h, p, sig = result
    assert h["alg"] == "HS256"
    assert p["sub"] == "1"


def test_jwt_parts_invalid():
    assert jwt_parts("not.a.valid.jwt.token") is None
    assert jwt_parts("garbage") is None
