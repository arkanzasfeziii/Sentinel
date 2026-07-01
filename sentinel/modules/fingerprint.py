"""Fingerprint module — detect tech stack, WAF, API framework, discover hidden endpoints."""

from __future__ import annotations

from typing import Any

from sentinel.data import COMMON_API_PATHS, WAF_SIGNATURES
from sentinel.logger import log
from sentinel.models import AttackResult, EngagementSession
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request


class FingerprintModule(BaseModule):
    """Detect tech stack, WAF, API framework, discover hidden endpoints."""

    name = "fingerprint"

    def run(self, es: EngagementSession, **kwargs: object) -> list[AttackResult]:
        results: list[AttackResult] = []
        log(f"[Fingerprint] Target: {es.base_url}", "INFO")

        # 1. Base response analysis
        resp = request(es, "GET", es.base_url)
        if not resp:
            results.append(AttackResult("fingerprint", "base_request", "ERROR",
                                        url=es.base_url, evidence="No response"))
            return results

        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        tech: list[str] = []

        if server:
            tech.append(f"Server: {server}")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
        if "laravel" in resp.text.lower():
            tech.append("Laravel (PHP)")
        if "django" in resp.text.lower():
            tech.append("Django (Python)")
        if "rails" in resp.text.lower():
            tech.append("Ruby on Rails")
        if "express" in resp.text.lower():
            tech.append("Express.js (Node)")
        if "spring" in resp.text.lower():
            tech.append("Spring (Java)")
        if "wordpress" in resp.text.lower():
            tech.append("WordPress")
        if "wp-content" in resp.text:
            tech.append("WordPress")
        if "struts" in resp.text.lower():
            tech.append("Apache Struts")

        log(f"[Fingerprint] Tech stack: {', '.join(tech) or 'Unknown'}", "OK")

        # 2. WAF detection
        waf_detected = []
        all_headers_str = " ".join(f"{k}={v}" for k, v in resp.headers.items()).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig.lower() in all_headers_str for sig in sigs):
                waf_detected.append(waf)
        # Probe WAF with known-bad payload
        probe_resp = request(es, "GET", es.base_url, params={"q": "' OR 1=1--"})
        if probe_resp and probe_resp.status_code in (403, 406, 429, 503):
            waf_detected.append("WAF-blocked (403/406/429/503 on SQL probe)")

        # 3. API endpoint discovery
        found_endpoints: list[dict[str, Any]] = []
        for path in COMMON_API_PATHS:
            url = es.base_url.rstrip("/") + path
            r = request(es, "GET", url)
            if r and r.status_code not in (404, 410):
                content_type = r.headers.get("Content-Type", "")
                found_endpoints.append({
                    "path": path, "status": r.status_code,
                    "size": len(r.content),
                    "content_type": content_type,
                    "notes": "JSON" if "json" in content_type else ("GraphQL" if "graphql" in path else ""),
                })
                log(f"[Fingerprint] Found: {path} [{r.status_code}]", "OK" if r.status_code < 400 else "WARN")

        # 4. GraphQL detection
        graphql_url = ""
        for ep in found_endpoints:
            if "graphql" in ep["path"].lower():
                graphql_url = es.base_url.rstrip("/") + ep["path"]
                break

        # 5. CORS misconfiguration
        cors_vulns = []
        cors_r = request(es, "GET", es.base_url, headers={"Origin": "https://evil.attacker.com"})
        if cors_r:
            acao = cors_r.headers.get("Access-Control-Allow-Origin", "")
            acac = cors_r.headers.get("Access-Control-Allow-Credentials", "")
            if "evil.attacker.com" in acao or acao == "*":
                cors_vulns.append({"header": "ACAO", "value": acao, "credentials": acac})
                if acac.lower() == "true":
                    log("[Fingerprint] CRITICAL CORS: reflects origin + allows credentials!", "CRIT")

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
