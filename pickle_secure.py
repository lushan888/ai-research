"""
Secure pickle module for ai-research (#739 fix).
All pickle operations require HMAC signature verification.
"""
import hashlib, hmac, json, os, pickle, secrets

_SECRET = os.environ.get("PICKLE_HMAC_SECRET") or secrets.token_hex(32)


def secure_dumps(obj) -> bytes:
    """Serialize with HMAC signature."""
    if isinstance(obj, (dict, list, str, int, float, bool, type(None))):
        payload = json.dumps(obj, ensure_ascii=False).encode()
        tag = b"json"
    else:
        payload = pickle.dumps(obj)
        tag = b"pickle"
    sig = hmac.new(_SECRET.encode(), payload, hashlib.sha256).digest()
    return tag + sig + payload


def secure_loads(data: bytes) -> object:
    """Deserialize with HMAC verification."""
    if len(data) < 34:
        raise ValueError("Data too short")
    tag = data[:4]
    sig = data[4:36]
    payload = data[36:]
    expected = hmac.new(_SECRET.encode(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Signature mismatch: data tampered or untrusted")
    if tag == b"json":
        return json.loads(payload)
    if tag == b"pickle":
        return pickle.loads(payload)
    raise ValueError(f"Unknown format: {tag}")
