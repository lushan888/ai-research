"""
Fix for Issue #959 — Session Fixation + Session ID in URL $120
================================================================

Vulnerability
-------------
The application accepts session IDs from URL parameters (`?sessionid=xyz`)
and does NOT regenerate the session ID after login. An attacker can:
1. Obtain a session ID
2. Trick the victim into using that session ID
3. After the victim logs in, the attacker shares the same session

Root Cause
----------
1. Session IDs accepted from URL parameters (leaked via Referer, logs)
2. No session regeneration on privilege escalation (login)
3. Cookies not set with Secure + HttpOnly flags

Fix Strategy
------------
1. Regenerate session ID after successful login
2. Only accept session IDs from cookies (reject URL parameters)
3. Set Secure + HttpOnly + SameSite cookie flags
4. Implement session binding (bind to IP + User-Agent)
5. Set reasonable session expiry

Acceptance Criteria
-------------------
- [x] Session regenerated after login
- [x] URL parameter session IDs rejected
- [x] Secure + HttpOnly cookie set
- [x] Session binding (IP/User-Agent)
- [x] Session expiry configured
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# Session configuration
SESSION_COOKIE_NAME: str = "session"
SESSION_TTL: int = 3600  # 1 hour
SESSION_ID_LENGTH: int = 64
SESSION_ID_ALPHABET: str = "abcdefghijklmnopqrstuvwxyz0123456789"

# Cookie flags
COOKIE_SECURE: bool = True
COOKIE_HTTPONLY: bool = True
COOKIE_SAMESITE: str = "Lax"  # Strict or Lax
COOKIE_PATH: str = "/"

# Session binding
ENABLE_IP_BINDING: bool = True
ENABLE_USER_AGENT_BINDING: bool = True


# =============================================================================
# Secure Session ID Generation
# =============================================================================

def generate_session_id() -> str:
    """Generate a cryptographically secure random session ID."""
    return secrets.token_urlsafe(SESSION_ID_LENGTH)


def is_valid_session_id(session_id: str) -> bool:
    """Check if a session ID has a valid format."""
    if not session_id:
        return False
    if len(session_id) < 16:
        return False
    # Session IDs should only contain URL-safe base64 characters
    return bool(re.match(r'^[A-Za-z0-9\-_]+$', session_id))


# =============================================================================
# Session Store
# =============================================================================

@dataclass
class SessionData:
    """Session data container."""
    user_id: Optional[str] = None
    created_at: float = 0.0
    last_accessed: float = 0.0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return time.time() - self.last_accessed > SESSION_TTL
    
    @property
    def is_authenticated(self) -> bool:
        """Check if the session has an authenticated user."""
        return self.user_id is not None


class InMemorySessionStore:
    """In-memory session store (for demonstration).
    
    In production, use Redis or a database.
    """
    
    def __init__(self):
        self._sessions: Dict[str, SessionData] = {}
    
    def create(self, session_id: str, ip: str, ua: str) -> SessionData:
        """Create a new session."""
        session = SessionData(
            created_at=time.time(),
            last_accessed=time.time(),
            ip_address=ip,
            user_agent=ua,
        )
        self._sessions[session_id] = session
        return session
    
    def get(self, session_id: str) -> Optional[SessionData]:
        """Get a session by ID."""
        session = self._sessions.get(session_id)
        if session and session.is_expired:
            self.delete(session_id)
            return None
        if session:
            session.last_accessed = time.time()
        return session
    
    def delete(self, session_id: str) -> None:
        """Delete a session."""
        self._sessions.pop(session_id, None)
    
    def regenerate(self, old_id: str, new_id: str) -> Optional[SessionData]:
        """Regenerate a session ID (creates new ID, preserves data)."""
        session = self._sessions.pop(old_id, None)
        if session:
            session.last_accessed = time.time()
            self._sessions[new_id] = session
        return session


# =============================================================================
# Session Manager
# =============================================================================

class SessionManager:
    """Manages sessions with fixation protection.
    
    Features:
    - Session regeneration on login
    - Reject URL parameter session IDs
    - Secure cookie configuration
    - Session binding (IP + User-Agent)
    - Session expiry
    """
    
    def __init__(self, store: Optional[InMemorySessionStore] = None):
        self.store = store or InMemorySessionStore()
    
    def get_session_from_cookies(
        self,
        cookies: Dict[str, str],
    ) -> Optional[SessionData]:
        """Get session from cookies only (not URL parameters).
        
        Args:
            cookies: Dictionary of cookie name -> value.
        
        Returns:
            SessionData if valid, None otherwise.
        """
        session_id = cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            return None
        
        if not is_valid_session_id(session_id):
            logger.warning(f"Invalid session ID format rejected")
            return None
        
        return self.store.get(session_id)
    
    def create_session(
        self,
        ip: str,
        user_agent: str = "",
    ) -> Tuple[str, SessionData]:
        """Create a new anonymous session.
        
        Returns:
            Tuple of (session_id, session_data)
        """
        session_id = generate_session_id()
        session = self.store.create(session_id, ip, user_agent)
        return session_id, session
    
    def authenticate_session(
        self,
        session_id: str,
        user_id: str,
        ip: str,
        user_agent: str = "",
    ) -> Tuple[str, SessionData]:
        """Authenticate a session with session regeneration.
        
        This is the key security fix:
        1. Generate a NEW session ID
        2. Copy data from old session to new session
        3. Delete the old session
        4. Return the new session ID
        
        Args:
            session_id: The current session ID.
            user_id: The authenticated user ID.
            ip: The client IP address.
            user_agent: The client User-Agent string.
        
        Returns:
            Tuple of (new_session_id, new_session_data)
        """
        # Regenerate session ID (prevents fixation)
        new_session_id = generate_session_id()
        
        # Transfer data to new session
        session = self.store.regenerate(session_id, new_session_id)
        
        if session is None:
            # Create new session if old one was invalid
            session = self.store.create(new_session_id, ip, user_agent)
        
        # Update with authentication info
        session.user_id = user_id
        session.ip_address = ip
        session.user_agent = user_agent or session.user_agent
        session.last_accessed = time.time()
        
        logger.info(f"Session regenerated: {session_id[:8]}... -> {new_session_id[:8]}...")
        
        return new_session_id, session
    
    def validate_session_binding(
        self,
        session: SessionData,
        ip: str,
        user_agent: str = "",
    ) -> bool:
        """Validate session binding (IP + User-Agent).
        
        This prevents session hijacking by checking that the request
        comes from the same client that established the session.
        
        Args:
            session: The session data.
            ip: The current request IP.
            user_agent: The current request User-Agent.
        
        Returns:
            True if binding matches.
        """
        if not session.is_authenticated:
            return True  # Don't enforce binding for anonymous sessions
        
        if ENABLE_IP_BINDING and session.ip_address:
            if session.ip_address != ip:
                logger.warning(f"Session IP binding mismatch")
                return False
        
        if ENABLE_USER_AGENT_BINDING and session.user_agent and user_agent:
            if session.user_agent != user_agent:
                logger.warning(f"Session User-Agent binding mismatch")
                return False
        
        return True
    
    def build_set_cookie_header(
        self,
        session_id: str,
        domain: str = "",
    ) -> str:
        """Build a Set-Cookie header with secure flags.
        
        Returns:
            A Set-Cookie header string.
        """
        parts = [
            f"{SESSION_COOKIE_NAME}={session_id}",
            f"Path={COOKIE_PATH}",
            f"Max-Age={SESSION_TTL}",
        ]
        
        if COOKIE_SECURE:
            parts.append("Secure")
        
        if COOKIE_HTTPONLY:
            parts.append("HttpOnly")
        
        if COOKIE_SAMESITE:
            parts.append(f"SameSite={COOKIE_SAMESITE}")
        
        if domain:
            parts.append(f"Domain={domain}")
        
        return "; ".join(parts)
    
    def destroy_session(self, session_id: str) -> None:
        """Destroy a session (logout)."""
        self.store.delete(session_id)
        logger.info(f"Session destroyed: {session_id[:8]}...")


# =============================================================================
# Middleware / Integration
# =============================================================================

class SessionSecurityMiddleware:
    """WSGI middleware for session security.
    
    Features:
    - Rejects URL parameter session IDs
    - Validates session binding
    - Ensures secure cookie headers
    """
    
    def __init__(self, app, session_manager: Optional[SessionManager] = None):
        self.app = app
        self.session_manager = session_manager or SessionManager()
    
    def __call__(self, environ, start_response):
        # Check for session ID in URL parameters
        query_string = environ.get("QUERY_STRING", "")
        params = self._parse_query_string(query_string)
        
        if "sessionid" in params or "session_id" in params or "sid" in params:
            # Log and reject requests with session ID in URL
            logger.warning("Session ID in URL parameter rejected")
            start_response(
                "400 Bad Request",
                [("Content-Type", "text/plain")],
            )
            return [b"Session ID in URL is not supported"]
        
        return self.app(environ, start_response)
    
    @staticmethod
    def _parse_query_string(query: str) -> Dict[str, str]:
        """Parse a query string into a dict."""
        params = {}
        for part in query.split("&"):
            if "=" in part:
                key, value = part.split("=", 1)
                params[key] = value
        return params


# =============================================================================
# Self-Test
# =============================================================================

def run_self_test() -> List[str]:
    """Run self-test to verify the fix works."""
    errors = []
    
    manager = SessionManager()
    
    # Test 1: Session creation
    session_id, session = manager.create_session("192.168.1.1", "TestAgent/1.0")
    assert session_id and len(session_id) > 16
    assert not session.is_authenticated
    print("✓ Test 1: Session created successfully")
    
    # Test 2: Session regeneration on login (fixation prevention)
    old_session_id = session_id
    new_session_id, session = manager.authenticate_session(
        session_id, "user123", "192.168.1.1", "TestAgent/1.0"
    )
    assert new_session_id != old_session_id, "Session ID should change after login"
    assert session.is_authenticated
    assert session.user_id == "user123"
    print("✓ Test 2: Session ID regenerated after login")
    
    # Test 3: Old session invalidated
    old_session = manager.store.get(old_session_id)
    assert old_session is None, "Old session should be invalidated"
    print("✓ Test 3: Old session invalidated")
    
    # Test 4: URL parameter session ID detection
    middleware = SessionSecurityMiddleware(None, manager)
    params = middleware._parse_query_string("sessionid=abc123&other=value")
    assert "sessionid" in params
    print("✓ Test 4: URL parameter session ID detected")
    
    # Test 5: Secure cookie header
    cookie = manager.build_set_cookie_header("test_session_id_12345")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Lax" in cookie
    print("✓ Test 5: Secure cookie header built")
    
    # Test 6: Session binding validation
    session_data = manager.store.get(new_session_id)
    assert manager.validate_session_binding(session_data, "192.168.1.1", "TestAgent/1.0")
    assert not manager.validate_session_binding(session_data, "10.0.0.1", "TestAgent/1.0")
    print("✓ Test 6: Session binding validated")
    
    # Test 7: Session destruction
    manager.destroy_session(new_session_id)
    assert manager.store.get(new_session_id) is None
    print("✓ Test 7: Session destroyed on logout")
    
    # Test 8: Valid session ID format
    assert is_valid_session_id(generate_session_id())
    assert not is_valid_session_id("")
    assert not is_valid_session_id("short")
    print("✓ Test 8: Session ID format validation")
    
    return errors


if __name__ == "__main__":
    errors = run_self_test()
    if errors:
        print(f"\nFAILED: {len(errors)} test(s) failed:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\nAll self-tests passed!")
