"""Boundary tests for all Sentinel attack modules — no crash on edge inputs."""

from sentinel.models import EngagementSession, HAS_REQUESTS


def _es(**kw) -> EngagementSession:
    defaults = dict(base_url="http://192.0.2.1", headers={}, cookies={},
                    proxies={}, timeout=2, delay=0.0)
    defaults.update(kw)
    return EngagementSession(**defaults)


# ── FingerprintModule ──────────────────────────────────────────────────────

def test_fingerprint_unreachable():
    from sentinel.modules.fingerprint import FingerprintModule
    es = _es()
    results = FingerprintModule().run(es)
    assert isinstance(results, list)


def test_fingerprint_empty_url():
    from sentinel.modules.fingerprint import FingerprintModule
    es = _es(base_url="")
    results = FingerprintModule().run(es)
    assert isinstance(results, list)


def test_fingerprint_https():
    from sentinel.modules.fingerprint import FingerprintModule
    es = _es(base_url="https://192.0.2.1")
    results = FingerprintModule().run(es)
    assert isinstance(results, list)


def test_fingerprint_with_port():
    from sentinel.modules.fingerprint import FingerprintModule
    es = _es(base_url="http://192.0.2.1:8080")
    results = FingerprintModule().run(es)
    assert isinstance(results, list)


def test_fingerprint_with_path():
    from sentinel.modules.fingerprint import FingerprintModule
    es = _es(base_url="http://192.0.2.1/api/v1")
    results = FingerprintModule().run(es)
    assert isinstance(results, list)


# ── SSRFModule ─────────────────────────────────────────────────────────────

def test_ssrf_unreachable():
    from sentinel.modules.ssrf import SSRFModule
    es = _es()
    results = SSRFModule().run(es)
    assert isinstance(results, list)


def test_ssrf_with_params():
    from sentinel.modules.ssrf import SSRFModule
    es = _es()
    results = SSRFModule().run(es, param_names=["url", "target", "redirect"])
    assert isinstance(results, list)


def test_ssrf_empty_params():
    from sentinel.modules.ssrf import SSRFModule
    es = _es()
    results = SSRFModule().run(es, param_names=[])
    assert isinstance(results, list)


def test_ssrf_none_params():
    from sentinel.modules.ssrf import SSRFModule
    es = _es()
    results = SSRFModule().run(es, param_names=None)
    assert isinstance(results, list)


def test_ssrf_localhost():
    from sentinel.modules.ssrf import SSRFModule
    es = _es(base_url="http://localhost:1")
    results = SSRFModule().run(es)
    assert isinstance(results, list)


# ── IDORModule ─────────────────────────────────────────────────────────────

def test_idor_unreachable():
    from sentinel.modules.idor import IDORModule
    es = _es()
    results = IDORModule().run(es, target_url="http://192.0.2.1/api/users/1",
                               target_id="1", id_param="")
    assert isinstance(results, list)


def test_idor_no_target_id():
    from sentinel.modules.idor import IDORModule
    es = _es()
    results = IDORModule().run(es, target_url="http://192.0.2.1/api/users",
                               target_id="", id_param="id")
    assert isinstance(results, list)


def test_idor_string_id():
    from sentinel.modules.idor import IDORModule
    es = _es()
    results = IDORModule().run(es, target_url="http://192.0.2.1/api/users/abc",
                               target_id="abc", id_param="")
    assert isinstance(results, list)


def test_idor_empty_everything():
    from sentinel.modules.idor import IDORModule
    es = _es()
    results = IDORModule().run(es, target_url="", target_id="", id_param="")
    assert isinstance(results, list)


def test_idor_large_id():
    from sentinel.modules.idor import IDORModule
    es = _es()
    results = IDORModule().run(es, target_url="http://192.0.2.1/api/users/99999999",
                               target_id="99999999", id_param="")
    assert isinstance(results, list)


# ── InjectModule ───────────────────────────────────────────────────────────

def test_inject_unreachable():
    from sentinel.modules.inject import InjectModule
    es = _es()
    results = InjectModule().run(es, target_url="http://192.0.2.1/search",
                                 params_to_test=["q"])
    assert isinstance(results, list)


def test_inject_no_params():
    from sentinel.modules.inject import InjectModule
    es = _es()
    results = InjectModule().run(es, target_url="http://192.0.2.1/search",
                                 params_to_test=None)
    assert isinstance(results, list)


def test_inject_empty_params():
    from sentinel.modules.inject import InjectModule
    es = _es()
    results = InjectModule().run(es, target_url="http://192.0.2.1",
                                 params_to_test=[])
    assert isinstance(results, list)


def test_inject_many_params():
    from sentinel.modules.inject import InjectModule
    es = _es()
    results = InjectModule().run(es, target_url="http://192.0.2.1",
                                 params_to_test=[f"p{i}" for i in range(20)])
    assert isinstance(results, list)


def test_inject_empty_url():
    from sentinel.modules.inject import InjectModule
    es = _es()
    results = InjectModule().run(es, target_url="", params_to_test=["q"])
    assert isinstance(results, list)


# ── GraphQLModule ──────────────────────────────────────────────────────────

def test_graphql_unreachable():
    from sentinel.modules.graphql import GraphQLModule
    es = _es()
    results = GraphQLModule().run(es, graphql_url="http://192.0.2.1/graphql")
    assert isinstance(results, list)


def test_graphql_no_url():
    from sentinel.modules.graphql import GraphQLModule
    es = _es()
    results = GraphQLModule().run(es, graphql_url="")
    assert isinstance(results, list)


def test_graphql_wrong_endpoint():
    from sentinel.modules.graphql import GraphQLModule
    es = _es()
    results = GraphQLModule().run(es, graphql_url="http://192.0.2.1/not-graphql")
    assert isinstance(results, list)


def test_graphql_https():
    from sentinel.modules.graphql import GraphQLModule
    es = _es()
    results = GraphQLModule().run(es, graphql_url="https://192.0.2.1/graphql")
    assert isinstance(results, list)


def test_graphql_default():
    from sentinel.modules.graphql import GraphQLModule
    es = _es(base_url="http://192.0.2.1")
    results = GraphQLModule().run(es)
    assert isinstance(results, list)


# ── AuthModule ─────────────────────────────────────────────────────────────

def test_auth_no_jwt():
    from sentinel.modules.auth import AuthModule
    es = _es()
    results = AuthModule().run(es, jwt_token="", oauth_client_id="", oauth_redirect="")
    assert isinstance(results, list)


def test_auth_invalid_jwt():
    from sentinel.modules.auth import AuthModule
    es = _es()
    results = AuthModule().run(es, jwt_token="not.valid.jwt", oauth_client_id="", oauth_redirect="")
    assert isinstance(results, list)


def test_auth_empty_oauth():
    from sentinel.modules.auth import AuthModule
    es = _es()
    results = AuthModule().run(es, jwt_token="", oauth_client_id="test-client", oauth_redirect="")
    assert isinstance(results, list)


def test_auth_all_empty():
    from sentinel.modules.auth import AuthModule
    es = _es()
    results = AuthModule().run(es)
    assert isinstance(results, list)


def test_auth_long_jwt():
    from sentinel.modules.auth import AuthModule
    es = _es()
    results = AuthModule().run(es, jwt_token="A" * 10000)
    assert isinstance(results, list)
