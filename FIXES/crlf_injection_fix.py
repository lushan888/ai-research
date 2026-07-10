"""
CRLF Injection in Access Log → HTTP Response Splitting Fix
Bounty #791 ($120)
=========================================
Vulnerability: HTTP access log writes User-Agent directly into response header:
res.setHeader("X-Log", userAgent)
Attacker injects \r\n to split response.

Fix: CRLF sanitization + never write user input to response headers.
"""

import re
from typing import Dict, Optional


class HeaderSanitizer:
    """
    Sanitizes HTTP headers to prevent CRLF injection.
    """

    @staticmethod
    def sanitize_header_value(value: str) -> str:
        """
        Remove or reject CRLF characters from header values.
        """
        # Remove CRLF characters entirely
        sanitized = value.replace('\r', '').replace('\n', '')
        # Also remove URL-encoded variants
        sanitized = sanitized.replace('%0d', '').replace('%0D', '')
        sanitized = sanitized.replace('%0a', '').replace('%0A', '')
        return sanitized

    @staticmethod
    def reject_crlf(value: str) -> Optional[str]:
        """
        Reject input containing CRLF entirely.
        Returns None if CRLF detected.
        """
        if '\r' in value or '\n' in value:
            return None
        if '%0d' in value.lower() or '%0a' in value.lower():
            return None
        return value

    @staticmethod
    def encode_header_value(value: str) -> str:
        """
        URL-encode value for safe header usage.
        """
        import urllib.parse
        return urllib.parse.quote(value, safe='')


class SecureAccessLogger:
    """
    Access log that doesn't write user input to response headers.
    """

    def __init__(self):
        self._log_buffer = []

    def log_request(self, ip: str, method: str, path: str,
                    user_agent: str) -> str:
        """
        Log access request.
        User-Agent is NOT written to response header.
        Instead, generates a sanitized log ID.
        """
        import hashlib
        import time

        # Generate a safe log entry ID (not user-controlled)
        log_id = hashlib.sha256(
            f"{ip}:{time.time()}:{path}".encode()
        ).hexdigest()[:12]

        # Store log internally (not in response header)
        self._log_buffer.append({
            "log_id": log_id,
            "ip": ip,
            "method": method,
            "path": path,
            "user_agent": user_agent,
            "timestamp": time.time(),
        })

        return log_id

    def get_safe_response_header(self, log_id: str) -> Dict[str, str]:
        """
        Get safe response headers.
        Only contains the log ID, never user input.
        """
        return {
            "X-Request-Log-Id": log_id,
            "X-Content-Type-Options": "nosniff",
        }


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== CRLF Injection Prevention ===")
    print()

    print("Attack:")
    malicious_ua = "NormalUA\r\nX-Hacked: true\r\n"
    print(f"  User-Agent: {malicious_ua}")
    print("  → HTTP response splitting!")
    print()

    print("Fix 1: Sanitize:")
    sanitized = HeaderSanitizer.sanitize_header_value(malicious_ua)
    print(f"  Sanitized: {repr(sanitized)}")

    print("Fix 2: Reject:")
    result = HeaderSanitizer.reject_crlf(malicious_ua)
    print(f"  Rejected: {result is None}")

    print("Fix 3: Don't write user input to headers:")
    logger = SecureAccessLogger()
    log_id = logger.log_request("192.168.1.1", "GET", "/api", malicious_ua)
    safe_headers = logger.get_safe_response_header(log_id)
    print(f"  Safe header: {safe_headers}")
    print()
    print("Measures:")
    print("✓ CRLF characters removed/rejected from input")
    print("✓ URL-encoded CRLF (%0d/%0a) also handled")
    print("✓ User input never written to response headers")
    print("✓ Use safe log ID instead of raw User-Agent")
    print("✓ URL encoding for safe header values")