"""Web and API attack modules."""

from sentinel.modules.auth import AuthModule
from sentinel.modules.fingerprint import FingerprintModule
from sentinel.modules.graphql import GraphQLModule
from sentinel.modules.idor import IDORModule
from sentinel.modules.inject import InjectModule
from sentinel.modules.ssrf import SSRFModule

__all__ = [
    "FingerprintModule", "SSRFModule", "IDORModule",
    "AuthModule", "InjectModule", "GraphQLModule",
]
