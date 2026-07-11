# Fix: MongoDB NoSQL Injection → Authentication Bypass

## Vulnerability

Login endpoints that pass user-supplied JSON fields directly into MongoDB queries are vulnerable to NoSQL injection. An attacker can inject MongoDB query operators such as `$ne` (not equal), `$gt` (greater than), `$regex`, or `$where` to bypass authentication entirely.

## Attack Vector

```javascript
// VULNERABLE: User input goes directly into MongoDB query
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    
    // Attacker sends: {"username": "admin", "password": {"$ne": ""}}
    // This matches any user where password is not empty → ALWAYS TRUE!
    const user = db.users.findOne({ username, password });
    
    if (user) {
        res.json({ success: true, token: createToken(user) });
    }
});
```

## Fix Implementation

### 1. Input Validation + Exact-Match Queries

```python
import hashlib
import os
from typing import Any

FORBIDDEN_OPERATORS = {
    "$ne", "$eq", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin", "$regex", "$exists", "$where",
}

def secure_login(body: dict, user_collection) -> dict | None:
    """Secure login handler preventing NoSQL injection."""
    
    # REJECT: operator injection
    for key, value in body.items():
        if isinstance(value, dict):
            for sub_key in value:
                if sub_key in FORBIDDEN_OPERATORS:
                    raise ValueError(f"Injection detected: {sub_key}")
            raise ValueError("Field must be string")
        if not isinstance(value, str):
            raise ValueError("Field must be string")
    
    # BUILD: exact-match query only (no password in query)
    query = {"username": body.get("username", "")}
    
    # LOOKUP: find user by exact username match
    user = user_collection.find_one(query)
    if not user:
        return None
    
    # VERIFY: server-side salted hash comparison
    stored_hash = user.get("password_hash", "")
    if not verify_password(body.get("password", ""), stored_hash):
        return None
    
    return user
```

### 2. Server-Side Password Hashing (PBKDF2)

```python
import hashlib
import os
import hmac

def hash_password(password: str) -> str:
    """Hash password with random salt."""
    salt = os.urandom(32)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        600000,  # iterations
    )
    return f"sha256$600000${encode_b64(salt)}${encode_b64(pwd_hash)}"

def verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification."""
    try:
        _, _, salt_b64, hash_b64 = stored.split("$")
        salt = decode_b64(salt_b64)
        expected = decode_b64(hash_b64)
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, 600000, dklen=len(expected)
        )
        return hmac.compare_digest(computed, expected)
    except (ValueError, IndexError):
        return False
```

### 3. Security Checklist

- [x] Reject MongoDB operators (`$ne`, `$gt`, `$regex`, `$where`, etc.)
- [x] Force input types to string (reject dict/array)
- [x] Use exact-match queries only for authentication
- [x] Server-side salted hash password comparison
- [x] Constant-time password verification
- [x] Password not included in database query

## References

- OWASP: Testing for NoSQL Injection
- MongoDB Documentation: Query Operators
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

## Wallet for Bounty Payment
- **ETH/EVM (Ethereum, Polygon, Base, Optimism, Arbitrum):** `0x415b24ab21388dbfb9c4da97cb1ab2b53ff21e29`
- **SOL (Solana):** `J6pwNJNbjYx7UHAvZK369kYRJHim8JVbeFEHRSqtFMjv`