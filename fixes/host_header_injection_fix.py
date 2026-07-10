"""
Host Header Injection → Password Reset Poisoning Fix
Bounty #784 ($120)
=========================================
Vulnerability: Password reset link uses Host header from request:
https://{Host}/reset?token=xyz. Attacker sets Host: attacker.com.

Fix: Use trusted hostname from config, never from request headers.
"""

from typing import Set, Optional
from urllib.parse import urlparse


class TrustedHostManager:
    """
    Manages trusted hostnames for URL generation.
    Never uses Host header from incoming requests.
    """

    # Default trusted hosts
    TRUSTED_HOSTS: Set[str] = {
        "example.com",
        "www.example.com",
        "api.example.com",
        "app.example.com",
    }

    def __init__(self, trusted_hosts: Optional[Set[str]] = None):
        self._trusted_hosts = trusted_hosts or self.TRUSTED_HOSTS
        self._canonical_host = "example.com"
        self._canonical_protocol = "https"

    def get_base_url(self) -> str:
        """Get the canonical base URL for generating links."""
        return f"{self._canonical_protocol}://{self._canonical_host}"

    def validate_host(self, host: str) -> bool:
        """Validate that a host is in the trusted whitelist."""
        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]
        return host in self._trusted_hosts

    def generate_password_reset_url(self, token: str) -> str:
        """
        Generate password reset URL using trusted hostname.
        NEVER uses Host header from request.
        """
        return f"{self.get_base_url()}/reset?token={token}"

    def generate_secure_link(self, path: str) -> str:
        """Generate any secure link using trusted hostname."""
        return f"{self.get_base_url()}{path}"


class SecureRequestHandler:
    """
    Request handler that prevents host header injection.
    """

    def __init__(self, host_manager: TrustedHostManager):
        self._host_manager = host_manager

    def process_password_reset(self, email: str,
                               request_host: str) -> dict:
        """
        Process password reset request.
        Uses trusted host, NOT request Host header.
        """
        # Generate reset token
        import secrets
        token = secrets.token_urlsafe(32)

        # Generate reset URL using TRUSTED host
        reset_url = self._host_manager.generate_password_reset_url(token)

        # Log the attempt with actual request host for audit
        return {
            "success": True,
            "reset_url": reset_url,
            "email": email,
            "request_host": request_host,
            "trusted_host": self._host_manager.get_base_url(),
            "_note": "URL generated with trusted host, request host logged for audit only",
        }

    def validate_and_process(self, email: str,
                             request_host: str) -> dict:
        """
        Validate host and process request.
        If host is untrusted, log warning but still use trusted host.
        """
        if not self._host_manager.validate_host(request_host):
            import logging
            logging.warning(
                f"Password reset request from untrusted host: {request_host}"
            )

        return self.process_password_reset(email, request_host)


# ========== Middleware Example ==========
class HostHeaderValidationMiddleware:
    """
    Middleware that validates Host header against whitelist.
    """

    def __init__(self, trusted_hosts: Set[str]):
        self._trusted_hosts = trusted_hosts

    def process_request(self, headers: dict) -> Optional[dict]:
        """
        Validate Host header.
        Returns error response if invalid, None if valid.
        """
        host = headers.get("Host") or headers.get("host")
        if not host:
            return {"error": "Missing Host header", "status": 400}

        # Strip port
        if ":" in host:
            host = host.split(":")[0]

        if host not in self._trusted_hosts:
            return {
                "error": "Invalid Host header",
                "status": 400,
                "expected_hosts": list(self._trusted_hosts),
            }

        return None


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Host Header Injection Prevention ===")
    print()

    # Attack scenario:
    # Attacker sets: Host: attacker.com
    # Vulnerable: https://{Host}/reset?token=xyz
    # → User receives: https://attacker.com/reset?token=xyz

    malicious_host = "attacker.com"
    print(f"Attack scenario:")
    print(f"  Request Host: {malicious_host}")
    print()

    # Before (vulnerable):
    vulnerable_url = f"https://{malicious_host}/reset?token=abc123"
    print(f"Vulnerable URL: {vulnerable_url}")
    print(f"  → User clicks attacker.com, token stolen!")
    print()

    # After (fixed):
    host_manager = TrustedHostManager()
    handler = SecureRequestHandler(host_manager)
    result = handler.process_password_reset("user@example.com", malicious_host)
    print(f"Fixed URL: {result['reset_url']}")
    print(f"  → Uses trusted host {host_manager.get_base_url()}")
    print(f"  → Attacker's host logged for audit: {result['request_host']}")
    print()

    print("=== Trusted Hosts ===")
    for host in sorted(host_manager.TRUSTED_HOSTS):
        print(f"  ✓ {host}")
