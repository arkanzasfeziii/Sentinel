"""HTTP request wrapper and JWT utilities."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from sentinel.models import EngagementSession, HAS_REQUESTS


def request(es: EngagementSession, method: str, url: str, **kwargs: Any) -> Optional[Any]:
    if not HAS_REQUESTS:
        return None
    try:
        time.sleep(es.delay)
        return es.session.request(method, url, timeout=es.timeout,
                                  allow_redirects=False, **kwargs)
    except Exception:
        return None


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def jwt_parts(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None
