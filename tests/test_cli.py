"""Tests for CLI."""

from sentinel.cli import MODULE_REGISTRY, build_parser


def test_all_modules_registered():
    expected = {"fingerprint", "ssrf", "idor", "auth", "inject", "graphql"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_default_modules():
    p = build_parser()
    args = p.parse_args(["--url", "http://target.com"])
    assert args.modules == ["fingerprint"]


def test_delay_default():
    p = build_parser()
    args = p.parse_args(["--url", "http://target.com"])
    assert args.delay == 0.3


def test_custom_header():
    p = build_parser()
    args = p.parse_args(["--url", "http://x", "-H", "Auth: Bearer token"])
    assert "Auth: Bearer token" in args.header


def test_proxy_flag():
    p = build_parser()
    args = p.parse_args(["--url", "http://x", "--proxy", "http://127.0.0.1:8080"])
    assert args.proxy == "http://127.0.0.1:8080"
