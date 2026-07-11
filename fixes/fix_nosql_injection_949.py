"""
Fix for Issue #949 — MongoDB NoSQL Injection → Authentication Bypass
====================================================================

Vulnerability
-------------
The login endpoint passes user-supplied JSON body fields directly into a
MongoDB query: ``db.users.find({username: body.username, password: body.password})``.
An attacker can inject MongoDB query operators such as ``$ne``, ``$gt``,
``$regex``, or ``$where`` to bypass authentication entirely.

Example attack payload::

    {"username": "admin", "password": {"$ne": ""}}

This causes the query to match any document where the password is not empty,
which is always true, so the attacker logs in as "admin" without knowing the
password.

Fix Strategy
------------
1. Never pass user input directly as MongoDB query operators.
2. Force all user-supplied values to be strings (reject dicts/arrays).
3. Reject known MongoDB operator keys (``$ne``, ``$gt``, ``$regex``, etc.).
4. Use server-side salted + hashed passwords for comparison.
5. Use exact-match queries only for authentication.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Mapping


# MongoDB operators that are forbidden in authentication queries
FORBIDDEN_OPERATORS = frozenset({
    "$ne", "$eq", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin", "$regex", "$exists", "$type",
    "$where", "$expr", "$mod", "$text", "$search",
    "$options", "$not", "$nor", "$or", "$and",
    "$all", "$elemMatch", "$size", "$bitsAllClear",
    "$bitsAllSet", "$bitsAnyClear", "$bitsAnySet",
    "$comment", "$natural",
})

# Field names that are allowed in authentication queries
ALLOWED_AUTH_FIELDS = frozenset({"username", "email"})

# PBKDF2 parameters
PBKDF2_ITERATIONS = 600000
HASH_ALGORITHM = "sha256"
SALT_LENGTH = 32
HASH_LENGTH = 32


class NoSQLInjectionError(ValueError):
    """Raised when a NoSQL injection attempt is detected."""


class SecureAuthQuery:
    """Secure authentication query builder that prevents NoSQL injection.

    Usage::

        auth = SecureAuthQuery()

        # Safe: returns exact-match query
        query = auth.build_login_query({"username": "admin", "password": "secret"})

        # Raises NoSQLInjectionError:
        query = auth.build_login_query({"username": "admin", "password": {"$ne": ""}})
    """

    @staticmethod
    def build_login_query(body: Mapping[str, Any]) -> dict[str, str]:
        """Build a safe MongoDB query from login request body.

        Args:
            body: The parsed JSON body from the login request.

        Returns:
            A safe exact-match query dict: ``{"username": "admin"}``

        Raises:
            NoSQLInjectionError: If the body contains operator injection.
        """
        if not isinstance(body, dict):
            raise NoSQLInjectionError("request body must be a JSON object")

        # Check for operator injection in any field
        for key, value in body.items():
            if key.startswith("$"):
                raise NoSQLInjectionError(
                    f"MongoDB operator injection detected: key {key!r} is not allowed"
                )

            if isinstance(value, dict):
                # Check for nested operator injection
                for sub_key in value:
                    if sub_key in FORBIDDEN_OPERATORS:
                        raise NoSQLInjectionError(
                            f"NoSQL operator injection detected: "
                            f"{key!r} contains forbidden operator {sub_key!r}"
                        )
                raise NoSQLInjectionError(
                    f"field {key!r} must be a string, not a dict"
                )

            if isinstance(value, list):
                raise NoSQLInjectionError(
                    f"field {key!r} must be a string, not an array"
                )

            if not isinstance(value, str):
                raise NoSQLInjectionError(
                    f"field {key!r} must be a string, got {type(value).__name__}"
                )

            # Reject keys that look like MongoDB operators
            if key in FORBIDDEN_OPERATORS:
                raise NoSQLInjectionError(
                    f"key {key!r} is a forbidden MongoDB operator"
                )

        # Build a safe exact-match query (only username/email, NOT password)
        # Password is verified separately via hash comparison
        safe_query: dict[str, str] = {}
        for field in ALLOWED_AUTH_FIELDS:
            if field in body:
                if not isinstance(body[field], str):
                    raise NoSQLInjectionError(f"field {field!r} must be a string")
                safe_query[field] = body[field]

        if not safe_query:
            raise NoSQLInjectionError(
                "login query must include at least one identifier field "
                f"({', '.join(sorted(ALLOWED_AUTH_FIELDS))})"
            )

        return safe_query

    @staticmethod
    def validate_password_input(password: Any) -> str:
        """Validate that the password input is a plain string.

        Args:
            password: The password value from the request body.

        Returns:
            The password as a string.

        Raises:
            NoSQLInjectionError: If the password is not a plain string.
        """
        if isinstance(password, dict):
            operators = [k for k in password if k in FORBIDDEN_OPERATORS]
            if operators:
                raise NoSQLInjectionError(
                    f"NoSQL operator injection detected in password: "
                    f"{', '.join(operators)}"
                )
            raise NoSQLInjectionError("password must be a string, not a dict")

        if isinstance(password, list):
            raise NoSQLInjectionError("password must be a string, not an array")

        if not isinstance(password, str):
            raise NoSQLInjectionError(
                f"password must be a string, got {type(password).__name__}"
            )

        if not password:
            raise NoSQLInjectionError("password must not be empty")

        return password


# ---------------------------------------------------------------------------
# Password hashing utilities (server-side salted hash)
# ---------------------------------------------------------------------------

class PasswordHasher:
    """Server-side password hashing with PBKDF2.

    Usage::

        hasher = PasswordHasher()
        hashed = hasher.hash_password("user_secret")
        # Store hashed in database

        # Verify
        assert hasher.verify_password("user_secret", hashed)
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password with a random salt using PBKDF2.

        Returns a string in the format: ``algorithm$iterations$salt$hash``
        """
        salt = os.urandom(SALT_LENGTH)
        pwd_hash = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
            dklen=HASH_LENGTH,
        )
        return _format_hash(HASH_ALGORITHM, PBKDF2_ITERATIONS, salt, pwd_hash)

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify a password against a stored hash using constant-time comparison."""
        try:
            algorithm, iterations_str, salt_b64, hash_b64 = stored_hash.split("$")
            iterations = int(iterations_str)
            salt = _decode_b64(salt_b64)
            expected_hash = _decode_b64(hash_b64)
        except (ValueError, IndexError):
            return False

        computed = hashlib.pbkdf2_hmac(
            algorithm,
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected_hash),
        )
        return hmac.compare_digest(computed, expected_hash)


def _format_hash(algorithm: str, iterations: int, salt: bytes, pwd_hash: bytes) -> str:
    """Format hash components into a single string."""
    return f"{algorithm}${iterations}${_encode_b64(salt)}${_encode_b64(pwd_hash)}"


def _encode_b64(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64(data: str) -> bytes:
    """Decode URL-safe base64 with padding recovery."""
    import base64
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ---------------------------------------------------------------------------
# Complete login handler example
# ---------------------------------------------------------------------------

def secure_login_handler(
    body: dict[str, Any],
    user_collection: Any,  # MongoDB collection
) -> dict[str, Any] | None:
    """Secure login handler that prevents NoSQL injection.

    Args:
        body: The parsed JSON request body.
        user_collection: A MongoDB collection object with ``find_one`` method.

    Returns:
        The user document if authentication succeeds, None otherwise.

    Raises:
        NoSQLInjectionError: If injection is detected.
    """
    # Step 1: Validate and build safe query
    query = SecureAuthQuery.build_login_query(body)

    # Step 2: Validate password input
    password = SecureAuthQuery.validate_password_input(body.get("password", ""))

    # Step 3: Look up user by identifier (exact match only)
    user = user_collection.find_one(query)

    if user is None:
        return None

    # Step 4: Verify password using server-side hash comparison
    stored_hash = user.get("password_hash", "")
    if not stored_hash:
        return None

    if not PasswordHasher.verify_password(password, stored_hash):
        return None

    return user