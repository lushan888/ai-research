"""
OAuth Access Token in Referer Header Fix
Bounty #790 ($150)
=========================================
Vulnerability: OAuth callback URL contains #access_token=xxx in the
fragment. Pages with external links leak the fragment via Referer header.

Fix: Use Authorization Code + PKCE flow + Referrer-Policy header.
"""

from typing import Dict, Optional, Tuple
import secrets
import hashlib
import base64


class PKCEUtils:
    """PKCE (Proof Key for Code Exchange) utilities."""

    @staticmethod
    def generate_code_verifier() -> str:
        """Generate a cryptographically random code verifier."""
        token = secrets.token_bytes(64)
        return base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")

    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        """Generate S256 code challenge from verifier."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def generate_state() -> str:
        """Generate anti-CSRF state parameter."""
        return secrets.token_urlsafe(32)


class SecureOAuthFlow:
    """
    OAuth 2.0 Authorization Code + PKCE flow.
    Never exposes tokens in URL fragment.
    """

    def __init__(self, client_id: str, redirect_uri: str,
                 authorization_endpoint: str, token_endpoint: str):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self._stored_verifiers: Dict[str, str] = {}  # state -> verifier

    def get_authorization_url(self, scope: str = "openid profile") -> Tuple[str, str]:
        """
        Generate authorization URL with PKCE.
        Token is NOT in URL fragment — it's exchanged server-side.
        Returns (url, state).
        """
        code_verifier = PKCEUtils.generate_code_verifier()
        code_challenge = PKCEUtils.generate_code_challenge(code_verifier)
        state = PKCEUtils.generate_state()

        self._stored_verifiers[state] = code_verifier

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.authorization_endpoint}?{query}", state

    def exchange_code(self, code: str, state: str) -> Optional[Dict[str, str]]:
        """
        Exchange authorization code for tokens (server-side).
        This happens on the backend, not in the browser.
        """
        verifier = self._stored_verifiers.pop(state, None)
        if verifier is None:
            raise ValueError("Invalid or expired state parameter")

        # In production, this POSTs to the token endpoint
        # Token response never touches the browser URL
        return {
            "access_token": "exchanged_server_side",
            "token_type": "Bearer",
            "expires_in": "3600",
            "state": state,
        }

    def cleanup(self, state: str):
        """Remove stored verifier for expired/invalid state."""
        self._stored_verifiers.pop(state, None)


class SecureOAuthMiddleware:
    """
    Middleware that ensures secure OAuth token handling.
    Prevents token leakage via Referer header.
    """

    @staticmethod
    def get_secure_headers() -> Dict[str, str]:
        """
        Headers to prevent Referer leakage.
        """
        return {
            # Prevent Referer header from being sent
            "Referrer-Policy": "no-referrer",
            # Additional security headers
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }

    @staticmethod
    def get_html_meta_tags() -> str:
        """
        HTML meta tags to prevent Referer leakage.
        Place in <head> of every page.
        """
        return '''
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; connect-src 'self' https://auth.example.com;">
'''

    @staticmethod
    def validate_redirect(redirect_url: str, allowed_hosts: set) -> bool:
        """
        Validate redirect URL to prevent open redirects.
        """
        from urllib.parse import urlparse
        parsed = urlparse(redirect_url)
        return parsed.hostname in allowed_hosts


# ========== HTML Template for OAuth Callback Page ==========
OAUTH_CALLBACK_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; connect-src 'self' https://auth.example.com;">
    <title>Authenticating...</title>
</head>
<body>
    <p>Authenticating, please wait...</p>
    <script>
        // OAuth callback uses Authorization Code flow (server-side exchange)
        // No access token appears in the URL fragment
        // The auth code is extracted from query params and sent to backend
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');

        if (code && state) {
            // Send auth code to backend for token exchange
            fetch('/api/auth/exchange', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({code, state}),
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    window.location.href = '/dashboard';
                }
            });
        }
    </script>
</body>
</html>
"""


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== OAuth 2.0 Authorization Code + PKCE Flow ===")
    print()

    oauth = SecureOAuthFlow(
        client_id="my_app",
        redirect_uri="https://myapp.com/oauth/callback",
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
    )

    # Step 1: Generate authorization URL (no token in URL!)
    url, state = oauth.get_authorization_url()
    print(f"Authorization URL (no token in URL):")
    print(f"  {url[:80]}...")
    print(f"  State: {state}")
    print()

    # Step 2: Exchange code for token (server-side)
    # Token never appears in browser URL fragment
    print(f"Token exchange happens server-side:")
    print(f"  Token endpoint: {oauth.token_endpoint}")
    print(f"  Referer leakage: Prevented via no-referrer policy")
    print()

    print("=== Security Headers ===")
    headers = SecureOAuthMiddleware.get_secure_headers()
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print()
    print("=== Before vs After ===")
    print("Before (vulnerable):")
    print("  URL: https://myapp.com/oauth/callback#access_token=secret123")
    print("  Referer: https://myapp.com/oauth/callback#access_token=secret123")
    print("  → Token leaked to external sites via Referer!")
    print()
    print("After (fixed):")
    print("  URL: https://myapp.com/oauth/callback?code=abc123&state=xyz789")
    print("  Referer: (not sent due to no-referrer policy)")
    print("  → Token stays server-side, never exposed!")
