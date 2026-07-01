"""Constants and configuration for Sentinel."""

from __future__ import annotations

from sentinel import __author__, __version__

TOOL_NAME = "Sentinel Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "sentinel"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SENTINEL — AUTHORIZED RED TEAM USE ONLY   ⚠                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL web attacks: SSRF to cloud metadata, IDOR     ║
║  enumeration, JWT/OAuth exploitation, SQL/NoSQL/SSTI injection, and         ║
║  GraphQL introspection abuse.                                                ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (URLs / endpoints / domains)                             ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

DEFAULT_TIMEOUT = 15
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
