"""
Timing Attack on Password Verification Fix
Bounty #788 ($120 Medium)
=========================================
Vulnerability: Password comparison is not constant-time, allowing
attackers to enumerate valid users and determine password length
via response timing.

Fix: Constant-time comparison + consistent response timing.
"""

import hmac
import time
from typing import Tuple


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time.
    Always compares the full length of the longer string.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class SecurePasswordVerifier:
    """Password verification with constant-time comparison and timing normalization."""

    # Minimum time to spend on verification (prevents timing leaks)
    MIN_VERIFICATION_TIME_MS = 50

    @classmethod
    def verify(cls, password: str, stored_hash: str, salt: str) -> Tuple[bool, float]:
        """
        Verify password in constant time with normalized response timing.
        Always takes at least MIN_VERIFICATION_TIME_MS regardless of input.
        """
        start = time.perf_counter()

        # Compute hash (simulated - real implementation uses bcrypt/argon2)
        computed_hash = cls._compute_hash(password, salt)

        # Constant-time comparison
        result = constant_time_compare(computed_hash, stored_hash)

        # Normalize timing: always spend the same minimum time
        elapsed = (time.perf_counter() - start) * 1000  # ms
        if elapsed < cls.MIN_VERIFICATION_TIME_MS:
            time.sleep((cls.MIN_VERIFICATION_TIME_MS - elapsed) / 1000)

        return result, max(elapsed, cls.MIN_VERIFICATION_TIME_MS)

    @staticmethod
    def _compute_hash(password: str, salt: str) -> str:
        """
        Simulate password hashing.
        In production, use bcrypt or argon2.
        """
        import hashlib
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        ).hex()


class AuthService:
    """Authentication service with timing-attack-resistant verification."""

    def __init__(self, user_repository):
        self._repo = user_repository

    def authenticate(self, username: str, password: str) -> dict:
        """
        Authenticate user with timing-safe password verification.
        Always returns consistent response timing regardless of whether
        the user exists or the password is correct.
        """
        user = self._repo.find_by_username(username)

        if user is None:
            # Use a dummy hash to normalize timing even for non-existent users
            dummy_hash = "0" * 64  # SHA-256 hex length
            dummy_salt = "dummy_salt"
            SecurePasswordVerifier.verify(password, dummy_hash, dummy_salt)
            return {"authenticated": False, "reason": "Invalid credentials"}

        verified, _ = SecurePasswordVerifier.verify(
            password, user.password_hash, user.salt
        )

        if not verified:
            return {"authenticated": False, "reason": "Invalid credentials"}

        return {"authenticated": True, "user_id": user.id}


# ========== Usage Example ==========
if __name__ == "__main__":
    # Demonstrate timing normalization
    import time

    verifier = SecurePasswordVerifier()

    # Timing should be consistent regardless of password correctness
    timings = []
    for password in ["a", "ab", "abc", "wrong_password_12345"]:
        start = time.perf_counter()
        result, _ = verifier.verify(password, "correct_hash_here", "my_salt")
        elapsed = (time.perf_counter() - start) * 1000
        timings.append(elapsed)
        print(f"Password '{password}': {result}, timing={elapsed:.1f}ms")

    # All timings should be within ~1ms of each other
    max_diff = max(timings) - min(timings)
    print(f"Max timing difference: {max_diff:.1f}ms (should be < 5ms)")
