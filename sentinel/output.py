"""Banner, legal warning, and result formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from sentinel.config import AUTHOR, LEGAL_WARNING, TOOL_NAME, VERSION
from sentinel.models import EngagementSession

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False


def print_banner() -> None:
    if HAS_PYFIGLET:
        print(f"\033[35m{pyfiglet.figlet_format('Sentinel', font='slant')}\033[0m")
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
    vulns = sum(1 for r in es.results if r.status == "VULN")
    crits = sum(1 for r in es.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═' * 60}\n  WEB ENGAGEMENT RESULTS\n{'═' * 60}\033[0m")
    print(f"  Total: {len(es.results)} | Vulns: \033[35m{vulns}\033[0m | Critical: \033[31m{crits}\033[0m\n")

    icons = {"VULN": "\033[35m[!]", "NOT_VULN": "\033[32m[✓]",
             "ERROR": "\033[31m[x]", "PARTIAL": "\033[33m[~]"}
    reset = "\033[0m"
    for r in es.results:
        c = icons.get(r.status, "\033[36m[*]")
        print(f"  {c}{reset} [{r.module}] {r.attack}")
        if r.url:
            print(f"        URL: {r.url}")
        if r.notes:
            print(f"        {r.notes}")

    if es.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(es.credentials)})\033[0m")
        for c in es.credentials:
            v = list(c.value.values())[0] if c.value else ""
            print(f"  [{c.type}] {c.source}: {str(v)[:60]}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION, "target": es.base_url,
            "results": [{"module": r.module, "attack": r.attack, "status": r.status,
                         "url": r.url, "severity": r.severity, "notes": r.notes}
                        for r in es.results],
            "credentials": [{"type": c.type, "value": c.value, "source": c.source}
                            for c in es.credentials],
            "loot": es.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")
