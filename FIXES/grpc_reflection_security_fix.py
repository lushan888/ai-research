"""
Fix for Issue #1155 - gRPC Reflection Enabled → Service Enumeration
Bounty: $120

Attack vector: gRPC server exposes the reflection API
(grpc.reflection.v1alpha.ServerReflection) in production. Attackers use
grpcurl or similar tools to enumerate all registered services, methods,
and message types, then target undocumented or admin endpoints.

Fix strategy:
1. Disable the reflection API entirely in production.
2. When reflection is needed, wrap it behind authentication (mTLS + service token).
3. Add an interceptor that validates credentials before serving reflection requests.
4. Separate internal vs external gRPC listeners.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set, Tuple


# --- Configuration ---

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


REFLECTION_METHOD_FULL_NAMES: Tuple[str, ...] = (
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
)

SENSITIVE_SERVICE_PATTERNS: Tuple[str, ...] = (
    "admin",
    "internal",
    "private",
    "debug",
    "secret",
    "billing",
    "root",
    "superuser",
    "management",
)


@dataclass
class GrpcSecurityConfig:
    """Security configuration for gRPC reflection access."""
    env: Environment = Environment.PRODUCTION
    require_mtls: bool = True
    require_service_token: bool = True
    allowed_service_tokens: Set[str] = field(default_factory=set)
    allowed_peers: Set[str] = field(default_factory=set)
    enable_reflection: bool = False  # Disabled by default in production


# --- Reflection Policy ---

class ReflectionAccess(Enum):
    DENY = "deny"
    ALLOW_WITH_MTLS = "allow_with_mtls"
    ALLOW_FULL = "allow_full"


@dataclass
class ReflectionAccessDecision:
    access: ReflectionAccess
    reason: str = ""


def evaluate_reflection_access(
    config: GrpcSecurityConfig,
    peer_identity: Optional[str] = None,
    service_token: Optional[str] = None,
    method_name: Optional[str] = None,
) -> ReflectionAccessDecision:
    """Determine whether a gRPC reflection request should be served.

    Args:
        config: Security configuration.
        peer_identity: TLS peer identity (CN or SAN).
        service_token: Bearer service token.
        method_name: Full gRPC method name being accessed.

    Returns:
        Access decision with reason.
    """
    # In production, reflection is off by default
    if config.env == Environment.PRODUCTION and not config.enable_reflection:
        return ReflectionAccessDecision(
            ReflectionAccess.DENY,
            "gRPC reflection is disabled in production"
        )

    if config.enable_reflection:
        # Check mTLS requirement
        if config.require_mtls:
            if not peer_identity:
                return ReflectionAccessDecision(
                    ReflectionAccess.DENY,
                    "mTLS peer identity required for reflection access"
                )
            if config.allowed_peers and peer_identity not in config.allowed_peers:
                return ReflectionAccessDecision(
                    ReflectionAccess.DENY,
                    f"Peer '{peer_identity}' not in allowed peers"
                )

        # Check service token requirement
        if config.require_service_token:
            if not service_token:
                return ReflectionAccessDecision(
                    ReflectionAccess.DENY,
                    "Service token required for reflection access"
                )
            if config.allowed_service_tokens and service_token not in config.allowed_service_tokens:
                return ReflectionAccessDecision(
                    ReflectionAccess.DENY,
                    "Invalid service token"
                )

        # Check if accessing a sensitive service
        if method_name:
            for pattern in SENSITIVE_SERVICE_PATTERNS:
                if pattern in method_name.lower():
                    return ReflectionAccessDecision(
                        ReflectionAccess.ALLOW_WITH_MTLS,
                        f"Sensitive service '{method_name}' requires mTLS"
                    )

        return ReflectionAccessDecision(
            ReflectionAccess.ALLOW_FULL,
            "Reflection access granted"
        )

    return ReflectionAccessDecision(
        ReflectionAccess.DENY,
        "Reflection not enabled"
    )


# --- Reflection Interceptor ---

class ReflectionInterceptor:
    """gRPC server interceptor that guards the reflection service.

    Usage with grpc.intercept_server:
        interceptor = ReflectionInterceptor(security_config)
        server = grpc.server(...)
        server = grpc.intercept_server(server, interceptor)
    """

    def __init__(self, config: GrpcSecurityConfig):
        self.config = config

    def intercept_service(self, continuation, handler_call_details):
        """Intercept incoming RPC calls before they reach the handler."""
        method_name = handler_call_details.method

        # Only intercept reflection methods
        if method_name not in REFLECTION_METHOD_FULL_NAMES:
            return continuation(handler_call_details)

        # Extract metadata (mTLS peer, service token) from call details
        metadata = dict(handler_call_details.invocation_metadata or [])
        peer_identity = metadata.get("x-forwarded-client-cert", None)
        service_token = metadata.get("authorization", None)
        if service_token and service_token.startswith("Bearer "):
            service_token = service_token[7:]

        decision = evaluate_reflection_access(
            self.config,
            peer_identity=peer_identity,
            service_token=service_token,
            method_name=method_name,
        )

        if decision.access == ReflectionAccess.DENY:
            # Return an unauthenticated gRPC error
            from grpc import StatusCode, RpcError

            class _DeniedRpcError(RpcError):
                def code(self):
                    return StatusCode.PERMISSION_DENIED
                def details(self):
                    return decision.reason

            raise _DeniedRpcError()

        return continuation(handler_call_details)


# --- Environment Helpers ---

def create_production_config(
    allowed_tokens: Optional[Set[str]] = None,
    allowed_peers: Optional[Set[str]] = None,
) -> GrpcSecurityConfig:
    """Create a secure gRPC config suitable for production.

    Reflection is disabled by default in production.
    """
    return GrpcSecurityConfig(
        env=Environment.PRODUCTION,
        require_mtls=True,
        require_service_token=True,
        allowed_service_tokens=set(allowed_tokens or []),
        allowed_peers=set(allowed_peers or []),
        enable_reflection=False,
    )


def create_development_config() -> GrpcSecurityConfig:
    """Create a relaxed gRPC config for development only.

    Never use this in production!
    """
    return GrpcSecurityConfig(
        env=Environment.DEVELOPMENT,
        require_mtls=False,
        require_service_token=False,
        enable_reflection=True,
    )


# --- Dual-listener setup example ---

def create_dual_listener_config(
    internal_peers: Set[str],
    service_tokens: Set[str],
) -> Tuple[GrpcSecurityConfig, GrpcSecurityConfig]:
    """Create two listener configs: external (locked down) + internal.

    Returns:
        (external_config, internal_config) tuple.
    """
    external = create_production_config()
    internal = GrpcSecurityConfig(
        env=Environment.PRODUCTION,
        require_mtls=True,
        require_service_token=True,
        allowed_service_tokens=service_tokens,
        allowed_peers=internal_peers,
        enable_reflection=True,  # Only on internal listener
    )
    return external, internal


# --- Unit Tests ---

import unittest


class TestGrpcReflectionFix(unittest.TestCase):

    def setUp(self):
        self.prod_config = create_production_config(
            allowed_tokens={"token-abc", "token-def"},
            allowed_peers={"internal-service.internal"}
        )

    def test_production_reflection_denied_by_default(self):
        decision = evaluate_reflection_access(self.prod_config)
        self.assertEqual(decision.access, ReflectionAccess.DENY)

    def test_mtls_required(self):
        config = GrpcSecurityConfig(
            env=Environment.PRODUCTION,
            require_mtls=True,
            enable_reflection=True,
        )
        decision = evaluate_reflection_access(config)
        self.assertEqual(decision.access, ReflectionAccess.DENY)
        self.assertIn("mTLS", decision.reason)

    def test_valid_mtls_and_token_grants_access(self):
        config = GrpcSecurityConfig(
            env=Environment.PRODUCTION,
            require_mtls=True,
            require_service_token=True,
            allowed_service_tokens={"token-xyz"},
            allowed_peers={"trusted-peer"},
            enable_reflection=True,
        )
        decision = evaluate_reflection_access(
            config,
            peer_identity="trusted-peer",
            service_token="token-xyz",
        )
        self.assertEqual(decision.access, ReflectionAccess.ALLOW_FULL)

    def test_development_reflection_allowed(self):
        config = create_development_config()
        decision = evaluate_reflection_access(config)
        self.assertEqual(decision.access, ReflectionAccess.ALLOW_FULL)

    def test_invalid_token_rejected(self):
        config = GrpcSecurityConfig(
            env=Environment.PRODUCTION,
            require_service_token=True,
            allowed_service_tokens={"correct-token"},
            enable_reflection=True,
        )
        decision = evaluate_reflection_access(
            config,
            service_token="wrong-token",
        )
        self.assertEqual(decision.access, ReflectionAccess.DENY)

    def test_sensitive_service_detected(self):
        config = GrpcSecurityConfig(
            env=Environment.PRODUCTION,
            require_mtls=True,
            enable_reflection=True,
        )
        decision = evaluate_reflection_access(
            config,
            method_name="/admin.SecretService/DoThing",
        )
        self.assertEqual(decision.access, ReflectionAccess.ALLOW_WITH_MTLS)

    def test_dual_listener_config(self):
        ext, intl = create_dual_listener_config(
            internal_peers={"internal-svc"},
            service_tokens={"svc-token"},
        )
        self.assertFalse(ext.enable_reflection)
        self.assertTrue(intl.enable_reflection)


if __name__ == "__main__":
    unittest.main()