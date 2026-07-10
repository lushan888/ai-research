"""
ECB Mode Encryption → Data Leak via Pattern Matching Fix
Bounty #796 ($120)
=========================================
Vulnerability: User data encrypted with AES-ECB. Same plaintext blocks
produce same ciphertext blocks. Attacker identifies "admin" vs "user" bits.

Fix: AES-GCM (authenticated encryption) with random IV.
"""

import os
import base64
from typing import Optional


class SecureEncryption:
    """
    Secure encryption using AES-GCM (AEAD).
    Replaces insecure AES-ECB.
    """

    def __init__(self, key: Optional[bytes] = None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        self._key = key
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt with AES-GCM.
        Uses random 12-byte nonce (IV) for each encryption.
        Returns: nonce + ciphertext + tag
        """
        nonce = os.urandom(12)  # Random IV every time
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        # ciphertext already includes the GCM tag
        return nonce + ciphertext

    def decrypt(self, encrypted: bytes, aad: bytes = b"") -> Optional[bytes]:
        """Decrypt AES-GCM ciphertext."""
        try:
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            return self._aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            return None

    def encrypt_str(self, plaintext: str) -> str:
        """Encrypt string and return base64-encoded result."""
        encrypted = self.encrypt(plaintext.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_str(self, encrypted_b64: str) -> Optional[str]:
        """Decrypt base64-encoded ciphertext."""
        try:
            encrypted = base64.b64decode(encrypted_b64)
            result = self.decrypt(encrypted)
            return result.decode() if result else None
        except Exception:
            return None


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== ECB Mode Prevention ===")
    print()

    key = os.urandom(32)
    enc = SecureEncryption(key)

    # Same plaintext encrypted twice → different ciphertext (GCM random IV)
    data = b"user: admin, role: admin"
    c1 = enc.encrypt(data)
    c2 = enc.encrypt(data)

    print(f"Same plaintext: {data}")
    print(f"Ciphertext 1: {c1.hex()[:40]}...")
    print(f"Ciphertext 2: {c2.hex()[:40]}...")
    print(f"Different: {c1 != c2}")
    print()

    # ECB would produce SAME ciphertext for SAME blocks
    # GCM produces DIFFERENT ciphertext every time (random IV)
    print("ECB vs GCM:")
    print("  ECB:  same plaintext → same ciphertext (pattern leak!)")
    print("  GCM:  same plaintext → different ciphertext (secure)")
    print()
    print("Measures:")
    print("✓ AES-GCM (authenticated encryption)")
    print("✓ Random 12-byte nonce (IV) per encryption")
    print("✓ No ECB mode used")
    print("✓ AEAD (authenticated encryption with associated data)")
    print("✓ Tamper detection via GCM authentication tag")