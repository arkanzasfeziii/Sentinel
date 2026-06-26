# Architecture

```
sentinel/
├── cli.py               # CLI, module dispatch
├── config.py            # Metadata, legal warning, defaults
├── models.py            # AttackResult, SSRFHit, Credential, EngagementSession
├── logger.py            # Colored logging
├── output.py            # Banner, results, JSON export
├── exceptions.py        # Typed exceptions
├── modules/
│   ├── base.py          # BaseModule ABC
│   ├── fingerprint.py   # Web server fingerprinting
│   ├── ssrf.py          # SSRF to cloud metadata
│   ├── idor.py          # IDOR enumeration
│   ├── auth.py          # JWT none/alg-switch, OAuth redirect abuse
│   ├── inject.py        # SQL/NoSQL/SSTI/command injection
│   └── graphql.py       # Introspection, batch query, DoS
├── utils/
│   └── http.py          # Request wrapper, JWT parser, base64url
└── data/
    └── __init__.py      # SSRF URLs, SQL payloads, JWT algos, GraphQL queries
```
