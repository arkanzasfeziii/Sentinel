"""Tests for data models."""

from sentinel.models import AttackResult, Credential, SSRFHit


def test_attack_result_defaults():
    r = AttackResult(module="ssrf", attack="cloud_metadata", status="VULN")
    assert r.severity == "INFO"
    assert r.url == ""


def test_ssrf_hit():
    h = SSRFHit(url="http://x", ssrf_param="url", ssrf_url="http://169.254.169.254",
                response="role-name", cloud="AWS", critical=True)
    assert h.critical is True


def test_credential():
    c = Credential(type="jwt", value={"token": "eyJ..."}, source="auth")
    assert c.type == "jwt"
