"""Boundary tests for sentinel.output, sentinel.logger, sentinel.exceptions, sentinel.cli."""

import os
import tempfile

from sentinel.cli import MODULE_REGISTRY, build_parser
from sentinel.exceptions import DependencyError, SentinelError
from sentinel.logger import log
from sentinel.models import AttackResult, EngagementSession
from sentinel.output import dump_results


# ── log ─────────────────────────────────────────────────────────────────────

def test_log_empty():
    log("", "INFO")


def test_log_unknown_level():
    log("msg", "FAKE")


def test_log_very_long():
    log("X" * 10000, "WARN")


def test_log_unicode():
    log("日本語テスト", "OK")


def test_log_vuln_level():
    log("found vuln", "VULN")


# ── dump_results ────────────────────────────────────────────────────────────

def _es(**kw):
    defaults = dict(base_url="http://test", headers={}, cookies={},
                    proxies={}, timeout=5, delay=0)
    defaults.update(kw)
    return EngagementSession(**defaults)


def test_dump_empty():
    dump_results(_es(), None)


def test_dump_with_results():
    es = _es()
    es.results = [AttackResult("ssrf", "probe", "VULN", severity="CRITICAL", notes="found")]
    dump_results(es, None)


def test_dump_to_file():
    es = _es()
    es.results = [AttackResult("test", "test", "VULN")]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    dump_results(es, path)
    assert os.path.exists(path)
    os.unlink(path)


def test_dump_many():
    es = _es()
    es.results = [AttackResult(f"m{i}", f"a{i}", "VULN", notes="n") for i in range(200)]
    dump_results(es, None)


def test_dump_with_creds():
    from sentinel.models import Credential
    es = _es()
    es.credentials = [Credential("jwt", {"token": "eyJ..."}, "auth")]
    dump_results(es, None)


# ── build_parser ────────────────────────────────────────────────────────────

def test_parser_minimal():
    args = build_parser().parse_args(["--url", "http://x"])
    assert args.url == "http://x"


def test_parser_all_modules():
    args = build_parser().parse_args(["--url", "http://x", "--modules", "all"])
    assert "all" in args.modules


def test_parser_proxy():
    args = build_parser().parse_args(["--url", "http://x", "--proxy", "http://127.0.0.1:8080"])
    assert args.proxy == "http://127.0.0.1:8080"


def test_parser_custom_header():
    args = build_parser().parse_args(["--url", "http://x", "-H", "Auth: Bearer tok"])
    assert "Auth: Bearer tok" in args.header


def test_parser_cookies():
    args = build_parser().parse_args(["--url", "http://x", "-C", "sess=abc123"])
    assert "sess=abc123" in args.cookie


# ── exceptions ──────────────────────────────────────────────────────────────

def test_sentinel_error():
    assert str(SentinelError("test")) == "test"


def test_dep_error():
    e = DependencyError("requests")
    assert "requests" in str(e)


def test_dep_inherits():
    assert isinstance(DependencyError("x"), SentinelError)


def test_module_registry_complete():
    expected = {"fingerprint", "ssrf", "idor", "auth", "inject", "graphql"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_module_registry_callable():
    for name, (cls, _) in MODULE_REGISTRY.items():
        assert callable(cls)
