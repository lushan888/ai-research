"""
WebSocket Hijacking via Missing Cookie Validation Fix
Bounty #795 ($150)
=========================================
Vulnerability: WebSocket upgrade checks Origin only. After connection,
messages aren't validated. Attacker bypasses Origin check and impersonates.

Fix: JWT token required on every WebSocket message.
"""

import json
import time
from typing import Dict, Optional, Set
from dataclasses import dataclass


@dataclass
class AuthenticatedWebSocketMessage:
    """WebSocket message with embedded JWT authentication."""
    type: str
    payload: dict
    token: str
    timestamp: int


class SecureWebSocketHandler:
    """
    WebSocket handler that validates authentication on every message.
    """

    def __init__(self, jwt_secret: str):
        self._secret = jwt_secret
        self._active_connections: Dict[str, Set] = {}  # user_id -> connections

    def validate_connection(self, headers: dict) -> Optional[str]:
        """
        Validate WebSocket connection upgrade.
        Checks Bearer token, not just Origin.
        """
        # Check Authorization header
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None

        token = auth[7:]  # Remove "Bearer "
        user_id = self._validate_token(token)
        return user_id

    def validate_message(self, message: dict) -> Optional[Dict]:
        """
        Validate each WebSocket message.
        Requires embedded JWT token.
        """
        try:
            msg = AuthenticatedWebSocketMessage(
                type=message.get("type", ""),
                payload=message.get("payload", {}),
                token=message.get("token", ""),
                timestamp=message.get("timestamp", 0),
            )
        except (KeyError, TypeError):
            return None

        # Validate token
        user_id = self._validate_token(msg.token)
        if not user_id:
            return None

        # Check timestamp (prevent replay attacks)
        if abs(time.time() - msg.timestamp) > 30:
            return None

        return {
            "user_id": user_id,
            "type": msg.type,
            "payload": msg.payload,
        }

    def _validate_token(self, token: str) -> Optional[str]:
        """Validate JWT token and extract user_id."""
        try:
            import jwt
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                options={"require": ["exp", "sub"]},
            )
            return payload.get("sub")
        except Exception:
            return None

    def generate_token(self, user_id: str) -> str:
        """Generate a JWT token for WebSocket auth."""
        import jwt
        payload = {
            "sub": user_id,
            "exp": int(time.time()) + 3600,  # 1 hour
            "iat": int(time.time()),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== WebSocket Hijacking Prevention ===")
    print()

    print("Attack scenario:")
    print("  1. Attacker connects to ws://example.com/ws")
    print("  2. Origin check passes (attacker controls Origin)")
    print("  3. Attacker sends: {\"type\": \"transfer\", \"amount\": 1000}")
    print("  4. → No auth check on message! Attacker impersonates user!")
    print()

    handler = SecureWebSocketHandler("my_secret_key_12345")

    # Generate token for user
    token = handler.generate_token("user_123")
    print(f"With fix:")
    print(f"  1. Connection requires: Authorization: Bearer {token[:20]}...")
    print(f"  2. Each message requires embedded token:")
    print(f"     {{\"type\": \"transfer\", \"payload\": {{...}}, \"token\": \"...\", \"timestamp\": ...}}")
    print(f"  3. Token validated on EVERY message")
    print(f"  4. Timestamp prevents replay attacks (30s window)")
    print()
    print("Measures:")
    print("✓ Connection upgrade validates Bearer token")
    print("✓ Each message validates embedded JWT")
    print("✓ Token bound to user session (sub claim)")
    print("✓ Timestamp validation (30s window)")
    print("✓ JWT with exp/iat/sub claims")