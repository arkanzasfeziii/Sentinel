"""Data models used across all Sentinel modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class AttackResult:
    module: str
    attack: str
    status: str
    url: str = ""
    payload: str = ""
    evidence: str = ""
    data: Any = None
    severity: str = "INFO"
    notes: str = ""


@dataclass
class SSRFHit:
    url: str
    ssrf_param: str
    ssrf_url: str
    response: str
    cloud: str
    critical: bool


@dataclass
class Credential:
    type: str
    value: Dict[str, str]
    source: str
    notes: str = ""


@dataclass
class EngagementSession:
    base_url: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    proxies: Dict[str, str]
    timeout: int
    delay: float
    results: List[AttackResult] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    loot: Dict[str, Any] = field(default_factory=dict)
    session: Any = None

    def __post_init__(self) -> None:
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update(self.headers)
            self.session.cookies.update(self.cookies)
            if self.proxies:
                self.session.proxies.update(self.proxies)
            retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
