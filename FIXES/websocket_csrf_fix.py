"""
Fix for Issue #939 — WebSocket CSRF → Cross-Origin Data Exfiltration $150
============================================================================

Vulnerability
-------------
WebSocket endpoint `/ws/realtime` lacks Origin validation. An attacker can
create a malicious page that uses the victim's authenticated session to
establish a WebSocket connection and steal real-time data.

Root Cause
----------
WebSocket connections are not protected by the same-origin policy that
applies to HTTP requests. The server must validate the Origin header.

Fix Strategy
------------
1. Implement Origin header whitelist validation for WebSocket connections.
2. Add CSRF challenge-response handshake before establishing connection.
3. Return 403 for invalid origins.
4. Use a cryptographically secure token for the handshake.

Acceptance Criteria
-------------------
- [x] Origin header whitelist validation
- [x] CSRF challenge-response before connection
- [x] Invalid origins return 403
- [x] Token-based handshake with expiry
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# Allowed origins for WebSocket connections
ALLOWED_WS_ORIGINS: Set[str] = frozenset({
    "https://example.com",
    "https://www.example.com",
    "https://app.example.com",
    "https://admin.example.com",
})

# CSRF token expiry (seconds)
CSRF_TOKEN_TTL: int = 300  # 5 minutes

# WebSocket path prefix to protect
WS_PATH_PREFIX: str = "/ws/"


# =============================================================================
# Origin Validation
# =============================================================================

@dataclass
class OriginValidationResult:
    """Result of WebSocket origin validation."""
    valid: bool
    error: Optional[str] = None


def validate_ws_origin(origin: Optional[str]) -> OriginValidationResult:
    """Validate the Origin header for WebSocket connections.
    
    Args:
        origin: The Origin header value from the WebSocket upgrade request.
    
    Returns:
        OriginValidationResult indicating whether the origin is allowed.
    """
    if not origin:
        return OriginValidationResult(
            valid=False,
            error="Missing Origin header",
        )
    
    # Normalize
    normalized = origin.lower().rstrip("/")
    
    if normalized in ALLOWED_WS_ORIGINS:
        return OriginValidationResult(valid=True)
    
    # Check for null origin (browser extensions, etc.)
    if normalized == "null":
        return OriginValidationResult(
            valid=False,
            error="Null origin not allowed",
        )
    
    return OriginValidationResult(
        valid=False,
        error=f"Origin '{origin}' not allowed",
    )


# =============================================================================
# CSRF Token Management
# =============================================================================

class WSCSRFTokenManager:
    """Manages CSRF tokens for WebSocket connections.
    
    Uses a challenge-response pattern:
    1. Client requests a challenge token
    2. Server returns a signed challenge
    3. Client includes the challenge in the WebSocket upgrade request
    4. Server verifies the challenge before accepting the connection
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        self._secret_key = secret_key or secrets.token_hex(32)
        self._used_tokens: Set[str] = set()
    
    def generate_challenge(self, user_id: str) -> str:
        """Generate a CSRF challenge token for a WebSocket connection.
        
        Args:
            user_id: The user identifier to bind the token to.
        
        Returns:
            A signed challenge token string.
        """
        token = secrets.token_hex(32)
        timestamp = int(time.time())
        payload = f"{user_id}:{token}:{timestamp}"
        signature = hmac.new(
            self._secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{payload}:{signature}"
    
    def verify_challenge(
        self,
        challenge: str,
        user_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """Verify a CSRF challenge token.
        
        Args:
            challenge: The challenge token from the client.
            user_id: The expected user identifier.
        
        Returns:
            Tuple of (valid: bool, error: Optional[str])
        """
        if not challenge:
            return False, "Missing challenge token"
        
        parts = challenge.split(":")
        if len(parts) != 4:
            return False, "Invalid challenge format"
        
        challenge_user_id, token, timestamp_str, signature = parts
        
        # Verify user binding
        if challenge_user_id != user_id:
            return False, "Challenge user mismatch"
        
        # Verify timestamp
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False, "Invalid timestamp"
        
        if time.time() - timestamp > CSRF_TOKEN_TTL:
            return False, "Challenge expired"
        
        # Verify signature
        payload = f"{challenge_user_id}:{token}:{timestamp_str}"
        expected_sig = hmac.new(
            self._secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid challenge signature"
        
        # Check for replay
        if challenge in self._used_tokens:
            return False, "Challenge already used"
        
        self._used_tokens.add(challenge)
        
        return True, None


# =============================================================================
# WebSocket Connection Validator
# =============================================================================

@dataclass
class WSConnectionResult:
    """Result of WebSocket connection validation."""
    allowed: bool
    status_code: int = 200
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


class WebSocketSecurityValidator:
    """Validates WebSocket connections for security.
    
    Checks:
    1. Origin header validation
    2. CSRF challenge verification
    3. Rate limiting
    """
    
    def __init__(
        self,
        token_manager: Optional[WSCSRFTokenManager] = None,
    ):
        self._token_manager = token_manager or WSCSRFTokenManager()
        self._connection_count: Dict[str, int] = {}
    
    def validate_connection(
        self,
        path: str,
        origin: Optional[str],
        user_id: Optional[str],
        csrf_challenge: Optional[str] = None,
    ) -> WSConnectionResult:
        """Validate a WebSocket connection request.
        
        Args:
            path: The WebSocket path.
            origin: The Origin header value.
            user_id: The authenticated user ID.
            csrf_challenge: The CSRF challenge token.
        
        Returns:
            WSConnectionResult indicating whether the connection is allowed.
        """
        # Only validate WebSocket paths
        if not path.startswith(WS_PATH_PREFIX):
            return WSConnectionResult(allowed=True)
        
        # Step 1: Validate origin
        origin_result = validate_ws_origin(origin)
        if not origin_result.valid:
            logger.warning(f"WebSocket rejected: {origin_result.error}")
            return WSConnectionResult(
                allowed=False,
                status_code=403,
                error=origin_result.error,
            )
        
        # Step 2: Verify CSRF challenge
        if user_id and csrf_challenge is not None:
            valid, error = self._token_manager.verify_challenge(
                csrf_challenge, user_id
            )
            if not valid:
                logger.warning(f"WebSocket CSRF rejected: {error}")
                return WSConnectionResult(
                    allowed=False,
                    status_code=403,
                    error=error,
                )
        elif user_id:
            # No CSRF challenge provided for authenticated user
            return WSConnectionResult(
                allowed=False,
                status_code=403,
                error="CSRF challenge required",
            )
        
        # Step 3: Rate limiting
        if user_id:
            count = self._connection_count.get(user_id, 0)
            if count > 10:  # Max 10 concurrent connections
                return WSConnectionResult(
                    allowed=False,
                    status_code=429,
                    error="Too many connections",
                )
            self._connection_count[user_id] = count + 1
        
        return WSConnectionResult(
            allowed=True,
            headers={
                "Sec-WebSocket-Protocol": "wss",
            },
        )
    
    def release_connection(self, user_id: str) -> None:
        """Release a WebSocket connection from rate limiting."""
        if user_id in self._connection_count:
            self._connection_count[user_id] = max(
                0, self._connection_count[user_id] - 1
            )


# =============================================================================
# Self-Test
# =============================================================================

def run_self_test() -> List[str]:
    """Run self-test to verify the fix works."""
    errors = []
    
    token_manager = WSCSRFTokenManager("test_secret_key_12345")
    validator = WebSocketSecurityValidator(token_manager)
    
    # Test 1: Valid origin
    result = validator.validate_connection(
        "/ws/realtime",
        "https://example.com",
        "user123",
        token_manager.generate_challenge("user123"),
    )
    assert result.allowed, "Test 1 failed: Valid origin should be allowed"
    print("✓ Test 1: Valid origin allowed")
    
    # Test 2: Invalid origin
    result = validator.validate_connection(
        "/ws/realtime",
        "https://evil.com",
        "user123",
        token_manager.generate_challenge("user123"),
    )
    assert not result.allowed, "Test 2 failed: Invalid origin should be rejected"
    assert result.status_code == 403
    print("✓ Test 2: Invalid origin rejected with 403")
    
    # Test 3: Missing origin
    result = validator.validate_connection(
        "/ws/realtime",
        None,
        "user123",
        token_manager.generate_challenge("user123"),
    )
    assert not result.allowed, "Test 3 failed: Missing origin should be rejected"
    print("✓ Test 3: Missing origin rejected")
    
    # Test 4: Missing CSRF challenge
    result = validator.validate_connection(
        "/ws/realtime",
        "https://example.com",
        "user123",
        None,
    )
    assert not result.allowed, "Test 4 failed: Missing CSRF should be rejected"
    print("✓ Test 4: Missing CSRF challenge rejected")
    
    # Test 5: Invalid CSRF challenge
    result = validator.validate_connection(
        "/ws/realtime",
        "https://example.com",
        "user123",
        "invalid_challenge_token",
    )
    assert not result.allowed, "Test 5 failed: Invalid CSRF should be rejected"
    print("✓ Test 5: Invalid CSRF challenge rejected")
    
    # Test 6: Non-WebSocket path not validated
    result = validator.validate_connection(
        "/api/data",
        "https://evil.com",
        None,
        None,
    )
    assert result.allowed, "Test 6 failed: Non-WS path should pass through"
    print("✓ Test 6: Non-WebSocket paths not validated")
    
    # Test 7: CSRF token expiry
    old_token = "user123:oldtoken:0:" + hmac.new(
        b"test_secret_key_12345",
        b"user123:oldtoken:0",
        hashlib.sha256,
    ).hexdigest()
    result = validator.validate_connection(
        "/ws/realtime",
        "https://example.com",
        "user123",
        old_token,
    )
    assert not result.allowed, "Test 7 failed: Expired CSRF should be rejected"
    print("✓ Test 7: Expired CSRF challenge rejected")
    
    return errors


if __name__ == "__main__":
    errors = run_self_test()
    if errors:
        print(f"\nFAILED: {len(errors)} test(s) failed:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\nAll self-tests passed!")
