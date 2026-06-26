"""Command-line interface for Sentinel."""

from __future__ import annotations

import argparse
import textwrap
from typing import Dict

from sentinel.config import COMMAND, DEFAULT_TIMEOUT, DEFAULT_UA, TOOL_NAME, VERSION
from sentinel.logger import log
from sentinel.models import AttackResult, EngagementSession, HAS_REQUESTS
from sentinel.modules import (
    AuthModule, FingerprintModule, GraphQLModule,
    IDORModule, InjectModule, SSRFModule,
)
from sentinel.output import dump_results, print_banner, print_legal

MODULE_REGISTRY = {
    "fingerprint": (FingerprintModule, lambda a: {}),
    "ssrf": (SSRFModule, lambda a: {"param_names": a.ssrf_params}),
    "idor": (IDORModule, lambda a: {"target_url": a.url, "target_id": a.target_id, "id_param": a.id_param}),
    "auth": (AuthModule, lambda a: {"jwt_token": a.jwt, "oauth_client_id": a.oauth_client, "oauth_redirect": a.oauth_redirect}),
    "inject": (InjectModule, lambda a: {"target_url": a.url, "params_to_test": a.params}),
    "graphql": (GraphQLModule, lambda a: {"graphql_url": a.graphql_url}),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --url https://target.com --modules fingerprint
              {COMMAND} --url https://target.com/api/fetch --modules ssrf
              {COMMAND} --url https://target.com --modules auth --jwt eyJhb...
              {COMMAND} --url https://target.com/api/search --modules inject --params q id
              {COMMAND} --url https://target.com/graphql --modules graphql
              {COMMAND} --url https://target.com --modules all -o findings.json
        """),
    )
    p.add_argument("--url", "-u", required=True)
    p.add_argument("--modules", nargs="+",
                   choices=["fingerprint", "ssrf", "idor", "auth", "inject", "graphql", "all"],
                   default=["fingerprint"])
    p.add_argument("--jwt", default="")
    p.add_argument("--target-id", default="")
    p.add_argument("--id-param", default="")
    p.add_argument("--params", nargs="+")
    p.add_argument("--graphql-url", default="")
    p.add_argument("--ssrf-params", nargs="+")
    p.add_argument("--oauth-client", default="")
    p.add_argument("--oauth-redirect", default="")
    p.add_argument("--header", "-H", action="append", default=[])
    p.add_argument("--cookie", "-C", action="append", default=[])
    p.add_argument("--proxy", default="")
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--output", "-o")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    if not print_legal(args.yes):
        print("Aborted.")
        return 1
    if not HAS_REQUESTS:
        log("requests not installed. Run: pip install requests", "ERR")
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
        headers=headers, cookies=cookies, proxies=proxies,
        timeout=args.timeout, delay=args.delay,
    )

    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        entry = MODULE_REGISTRY.get(mod_name)
        if not entry:
            continue
        mod_cls, kwargs_fn = entry
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            results = mod.run(es, **kwargs_fn(args))
            es.results.extend(results)
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")
            es.results.append(AttackResult(mod_name, "run", "ERROR", notes=str(exc)))

    dump_results(es, args.output)
    return 0
