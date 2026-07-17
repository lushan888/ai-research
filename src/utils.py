import os
import fcntl
import tempfile
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def atomic_write(data: bytes, destination: str) -> str:
    """
    Atomically write data to a file using a temporary file and rename.
    """
    dest = Path(destination).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    temp_fd = None
    temp_path = None
    try:
        temp_fd, temp_path = tempfile.mkstemp(
            dir=dest.parent,
            prefix=f".atomic_write_{dest.name}_"
        )
        
        with os.fdopen(temp_fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        
        os.replace(temp_path, dest)
        
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise
    
    return str(dest)


def encrypt_data(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt data using AES-GCM (authenticated encryption).
    Fixes ECB mode pattern matching vulnerability.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    return nonce + aesgcm.encrypt(nonce, plaintext.encode(), None)


def decrypt_data(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt data using AES-GCM.
    """
    nonce = ciphertext[:12]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext[12:], None).decode()


def generate_oauth_state() -> str:
    """
    Generate cryptographically secure OAuth state parameter.
    Fixes predictable OAuth state token vulnerability.
    """
    return secrets.token_urlsafe(32)


def validate_oauth_state(state: str, session_state: str) -> bool:
    """
    Validate OAuth state using constant-time comparison.
    """
    if not state or not session_state:
        return False
    return secrets.compare_digest(state, session_state)
