"""
TOTP Secret Leaked via QR Code in Logs Fix
Bounty #804 ($150)
=========================================
Vulnerability: 2FA setup QR code (otpauth://totp/...?secret=...) logged
to server logs. Insiders with log access can scan QR to get TOTP secret.

Fix: Log filters to mask secrets + QR generation not logged + audit logs.
"""

import re
from typing import Dict, List, Any


class SecureLogFilter:
    """
    Log filter that masks sensitive data.
    Prevents TOTP secrets, tokens, and passwords from being logged.
    """

    # Patterns for sensitive data
    SENSITIVE_PATTERNS = [
        (re.compile(r'(secret=)[^&\s]+'), r'\1****'),
        (re.compile(r'(token=)[^&\s]+'), r'\1****'),
        (re.compile(r'(password=)[^&\s]+'), r'\1****'),
        (re.compile(r'(api_key=)[^&\s]+'), r'\1****'),
        (re.compile(r'(access_token=)[^&\s]+'), r'\1****'),
        (re.compile(r'(refresh_token=)[^&\s]+'), r'\1****'),
        (re.compile(r'(otpauth://totp/\S+)'), '[TOTP_URI_REDACTED]'),
        (re.compile(r'"secret"\s*:\s*"[^"]+"'), '"secret": "****"'),
        (re.compile(r'"password"\s*:\s*"[^"]+"'), '"password": "****"'),
        (re.compile(r'"token"\s*:\s*"[^"]+"'), '"token": "****"'),
        (re.compile(r'[A-Za-z0-9+/=]{32,}'), '[POTENTIAL_SECRET_REDACTED]'),
    ]

    # URLs that should never be logged
    SENSITIVE_URL_PATTERNS = [
        re.compile(r'/2fa/setup'),
        re.compile(r'/totp/setup'),
        re.compile(r'/mfa/enable'),
        re.compile(r'/qrcode'),
    ]

    @classmethod
    def filter_log_line(cls, log_line: str) -> str:
        """Filter a single log line, masking sensitive data."""
        filtered = log_line
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            filtered = pattern.sub(replacement, filtered)
        return filtered

    @classmethod
    def is_sensitive_request(cls, url: str) -> bool:
        """Check if a request URL is sensitive and should not be logged."""
        for pattern in cls.SENSITIVE_URL_PATTERNS:
            if pattern.search(url):
                return True
        return False

    @classmethod
    def filter_log_dict(cls, log_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively filter a log dictionary, masking sensitive fields."""
        filtered = {}
        for key, value in log_dict.items():
            # Mask sensitive keys
            if any(s in key.lower() for s in ['secret', 'token', 'password',
                                                'apikey', 'api_key',
                                                'access_key', 'private_key']):
                filtered[key] = '****'
            elif isinstance(value, dict):
                filtered[key] = cls.filter_log_dict(value)
            elif isinstance(value, str):
                filtered[key] = cls.filter_log_line(value)
            else:
                filtered[key] = value
        return filtered


class SecureQRCodeGenerator:
    """
    QR code generator that doesn't leak secrets to logs.
    """

    def __init__(self, issuer: str = "MyApp"):
        self._issuer = issuer

    def generate_totp_uri(self, username: str, secret: str) -> str:
        """Generate TOTP URI without logging the secret."""
        import urllib.parse

        params = urllib.parse.urlencode({
            "secret": "REDACTED_FOR_LOG",  # Log-safe version
            "issuer": self._issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        })

        # Log-safe URI (no actual secret)
        log_safe_uri = f"otpauth://totp/{self._issuer}:{username}?{params}"
        return log_safe_uri

    def generate_qr_data_url(self, username: str, secret: str) -> str:
        """Generate QR code as data URL for display.
        The QR generation itself is NOT logged."""
        import base64
        import io
        import qrcode

        # Generate TOTP URI with REAL secret (only in memory)
        import urllib.parse
        real_params = urllib.parse.urlencode({
            "secret": secret,
            "issuer": self._issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        })
        real_uri = f"otpauth://totp/{self._issuer}:{username}?{real_params}"

        # Generate QR (not logged)
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(real_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        data_url = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"

        return data_url


class AuditLogger:
    """
    Separate audit log for sensitive operations.
    """

    def __init__(self, log_path: str = "/var/log/app/audit.log"):
        self._log_path = log_path

    def log_sensitive_action(self, action: str, user: str,
                             metadata: Dict = None):
        """Log to separate audit log (not main application log)."""
        import json
        import logging

        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)

        handler = logging.FileHandler(self._log_path)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(message)s'
        ))
        audit_logger.addHandler(handler)

        log_entry = {
            "action": action,
            "user": user,
            "metadata": metadata or {},
        }

        audit_logger.info(json.dumps(log_entry))


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== TOTP Secret Leak Prevention ===")
    print()

    print("Attack scenario:")
    print("  QR setup URL: otpauth://totp/MyApp:user?secret=JBSWY3DPEHPK3PXP")
    print("  → Logged to server logs!")
    print("  → Insider with log access scans QR to get TOTP secret")
    print()

    # Test log filtering
    log_line = "GET /2fa/setup?secret=JBSWY3DPEHPK3PXP HTTP/1.1 200"
    filtered = SecureLogFilter.filter_log_line(log_line)
    print(f"Before: {log_line}")
    print(f"After:  {filtered}")
    print()

    print("Measures:")
    print("✓ Log filters mask secret/token/password fields")
    print("✓ QR generation paths not logged (sensitive URL detection)")
    print("✓ Sensitive operations use separate audit log")
    print("✓ Log-safe TOTP URI generation (secret=REDACTED)")
    print("✓ Real TOTP secret only exists in memory during QR generation")