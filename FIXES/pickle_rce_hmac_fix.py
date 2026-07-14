"""
Pickle RCE via Cache System - Security Fix
===========================================
Issue: #739 (Expert, $200)
Vulnerability: Redis cache stores pickle.dumps() serialized sessions.
Attack: Malicious actor writes crafted pickle payload → pickle.loads() triggers RCE.

Fix: HMAC-signed pickle + JSON fallback
"""

import hashlib, hmac, json, os, pickle, secrets

# ============================================
# VULNERABLE CODE (BEFORE)
# ============================================
def vulnerable_cache_set(session_data):
    """
    ❌ VULNERABLE: Stores pickled session in Redis
    - Attacker can write malicious pickle payload
    - pickle.loads() will execute arbitrary code
    """
    import redis
    r = redis.Redis(host='localhost', port=6379)
    serialized = pickle.dumps(session_data)  # No signature!
    r.set(f"session:{session_data.get('user_id')}", serialized)


def vulnerable_cache_get(user_id):
    """
    ❌ VULNERABLE: Deserializes untrusted pickle
    - Attacker's payload executes on this line
    """
    import redis
    r = redis.Redis(host='localhost', port=6379)
    raw = r.get(f"session:{user_id}")
    if raw:
        return pickle.loads(raw)  # RCE HERE!
    return None


# ============================================
# SECURE CODE (AFTER)
# ============================================
SECRET_KEY = os.environ.get("PICKLE_HMAC_SECRET") or secrets.token_hex(32)


class SignedSessionStore:
    """
    ✅ SECURE: HMAC-signed session storage
    - Every serialized payload is signed with HMAC-SHA256
    - Deserialization verifies signature before unpickling
    - Tampered/malicious payloads are rejected
    """
    
    def __init__(self, redis_client, key_prefix="session"):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._secret = SECRET_KEY.encode()
    
    def _sign(self, payload: bytes) -> bytes:
        """Create HMAC-SHA256 signature."""
        return hmac.new(self._secret, payload, hashlib.sha256).digest()
    
    def set(self, user_id, session_data):
        """Store signed session data."""
        # Prefer JSON for structured data (no pickle needed)
        if isinstance(session_data, (dict, list)):
            payload = json.dumps(session_data, ensure_ascii=False).encode()
            sig = hmac.new(self._secret, payload, hashlib.sha256).digest()
            stored = b"__JSON__" + sig + b"__" + payload
        else:
            # Only pickle non-JSON-serializable objects
            payload = pickle.dumps(session_data)
            sig = hmac.new(self._secret, payload, hashlib.sha256).digest()
            stored = b"__PICKLE__" + sig + b"__" + payload
        
        key = f"{self.key_prefix}:{user_id}"
        self.redis.setex(key, 3600, stored)  # 1 hour TTL
    
    def get(self, user_id):
        """Retrieve and verify signed session data."""
        key = f"{self.key_prefix}:{user_id}"
        raw = self.redis.get(key)
        if not raw:
            return None
        
        # JSON path
        if raw.startswith(b"__JSON__"):
            marker_len = len(b"__JSON__")
            sig = raw[marker_len:marker_len+32]
            payload = raw[marker_len+32+2:]  # skip "__" separator
            expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise ValueError("Session signature mismatch: possible tampering")
            return json.loads(payload)
        
        # Pickle path (only for non-JSON objects)
        if raw.startswith(b"__PICKLE__"):
            marker_len = len(b"__PICKLE__")
            sig = raw[marker_len:marker_len+32]
            payload = raw[marker_len+32+2:]
            expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise ValueError("Session signature mismatch: possible tampering")
            return pickle.loads(payload)
        
        raise ValueError(f"Unknown session format: {raw[:20]}")
    
    def delete(self, user_id):
        """Delete session."""
        self.redis.delete(f"{self.key_prefix}:{user_id}")


# ============================================
# MIGRATION HELPER
# ============================================
def migrate_legacy_cache(redis_client, dry_run=True):
    """
    Migrate all existing legacy pickle sessions to signed format.
    - Scans all session keys
    - Rewrites them with HMAC signatures
    """
    import re
    pattern = re.compile(b"session:.*")
    migrated = 0
    for key in redis_client.scan_iter(match="session:*"):
        if isinstance(key, bytes):
            key = key.decode()
        raw = redis_client.get(key)
        if raw and not raw.startswith((b"__JSON__", b"__PICKLE__")):
            # Legacy unsigned pickle
            try:
                data = pickle.loads(raw)
                store = SignedSessionStore(redis_client)
                store.set(key.split(":", 1)[1], data)
                migrated += 1
                if not dry_run:
                    redis_client.delete(key)  # Remove legacy key
            except Exception:
                pass  # Skip corrupted legacy entries
    return migrated


# ============================================
# USAGE EXAMPLE
# ============================================
if __name__ == "__main__":
    import redis
    
    r = redis.Redis(host='localhost', port=6379, decode_responses=False)
    store = SignedSessionStore(r)
    
    # Safe storage
    store.set("user_123", {"username": "alice", "role": "admin"})
    
    # Safe retrieval (signature verified)
    session = store.get("user_123")
    print(f"Session: {session}")
    
    # Attempt tampering (will raise ValueError)
    r.set("session:hacker", b"__JSON__" + b"A"*32 + b"__{'admin': True}")
    try:
        store.get("hacker")
    except ValueError as e:
        print(f"Attack blocked: {e}")
