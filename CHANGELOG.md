# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Complete rewrite from single-file to modular package
- Each attack type is an independent module under sentinel/modules/
- HTTP/JWT helpers extracted to sentinel/utils/http.py
- Attack payloads extracted to sentinel/data/

### Added
- 14 unit tests (models, HTTP utils, CLI)
- pyproject.toml, Makefile, CI, Dockerfile
- docs/ARCHITECTURE.md
- LICENSE, CONTRIBUTING, SECURITY, CHANGELOG

## [1.0.0] - 2026-06-20

### Added
- Initial release: fingerprinting, SSRF, IDOR, JWT/OAuth,
  SQL/NoSQL/SSTI injection, GraphQL exploitation
