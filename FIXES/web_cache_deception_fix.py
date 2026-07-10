"""
Web Cache Deception Fix
Bounty #789 ($150)
=========================================
Vulnerability: CDN caches /assets/*.css regardless of content type.
Attacker tricks user into visiting /account/settings/nonexistent.css,
CDN caches the sensitive page (because .css extension matches),
attacker reads the cache to steal session tokens.

Fix: 
1. Cache rules based on Content-Type, not file extension
2. Sensitive pages return Cache-Control: no-store
3. CDN configured to not cache authenticated pages
"""

from typing import Dict, Optional, Set


class SecureCachePolicy:
    """
    Cache policy that prevents web cache deception attacks.
    
    Principles:
    1. Cache key includes Content-Type — .css extension alone is not enough
    2. Authenticated pages always return Cache-Control: no-store
    3. Static assets validated by Content-Type before caching
    """

    # Content types that are safe to cache
    CACHEABLE_CONTENT_TYPES: Set[str] = {
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "application/font-woff2",
        "application/font-woff",
        "font/woff2",
        "font/woff",
        "application/octet-stream",  # For font files
    }

    # Path prefixes for static assets
    STATIC_PATH_PREFIXES: Set[str] = {"/assets/", "/static/", "/public/"}

    # Sensitive paths that must never be cached
    SENSITIVE_PATHS: Set[str] = {
        "/account/", "/profile/", "/settings/",
        "/api/", "/auth/", "/login", "/logout",
        "/checkout/", "/payment/",
    }

    @classmethod
    def should_cache(cls, path: str, content_type: str,
                     is_authenticated: bool) -> bool:
        """
        Determine if a response should be cached.
        
        Returns False if:
        - User is authenticated
        - Path is sensitive
        - Content-Type is not a cacheable static asset
        - Path extension doesn't match content type
        """
        # Never cache authenticated responses
        if is_authenticated:
            return False

        # Never cache sensitive paths
        if cls._is_sensitive_path(path):
            return False

        # Only cache if content type is a known static asset type
        if content_type not in cls.CACHEABLE_CONTENT_TYPES:
            return False

        # Verify path is a static asset path
        if not cls._is_static_path(path):
            return False

        return True

    @classmethod
    def get_cache_headers(cls, path: str, content_type: str,
                          is_authenticated: bool) -> Dict[str, str]:
        """
        Generate appropriate Cache-Control headers.
        
        For sensitive/authenticated responses: no-store
        For static assets: public, immutable with max-age
        """
        if is_authenticated or cls._is_sensitive_path(path):
            return {
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }

        if cls.should_cache(path, content_type, is_authenticated):
            return {
                "Cache-Control": "public, max-age=31536000, immutable",
                "X-Content-Type-Options": "nosniff",
            }

        # Default: no caching
        return {
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }

    @classmethod
    def _is_sensitive_path(cls, path: str) -> bool:
        """Check if path is sensitive and should never be cached."""
        return any(path.startswith(prefix) for prefix in cls.SENSITIVE_PATHS)

    @classmethod
    def _is_static_path(cls, path: str) -> bool:
        """Check if path is a static asset path."""
        return any(path.startswith(prefix) for prefix in cls.STATIC_PATH_PREFIXES)


class CDNMiddleware:
    """
    Middleware that enforces secure caching policy.
    Prevents web cache deception attacks.
    """

    def __init__(self):
        self.cache_policy = SecureCachePolicy()

    def process_response(self, path: str, content_type: str,
                         is_authenticated: bool,
                         response_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Process response and add appropriate cache headers.
        """
        headers = dict(response_headers or {})
        cache_headers = self.cache_policy.get_cache_headers(
            path, content_type, is_authenticated
        )
        headers.update(cache_headers)

        # Always set X-Content-Type-Options: nosniff
        headers["X-Content-Type-Options"] = "nosniff"

        return headers


# ========== Nginx Configuration Example ==========
NGINX_CONFIG = """
# Nginx configuration to prevent Web Cache Deception

# Define cache zone
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=static_cache:10m max_size=1g inactive=60m;

# Only cache GET/HEAD requests with specific content types
map $upstream_http_content_type $cacheable_type {
    ~^text/css             1;
    ~^(text|application)/javascript  1;
    ~^image/              1;
    default               0;
}

# Block caching for authenticated requests
map $http_cookie $is_authenticated {
    ~session                1;
    ~token                  1;
    default                 0;
}

server {
    listen 80;
    server_name example.com;

    # Static assets - only cache if Content-Type matches
    location ~* \\.(css|js|png|jpg|jpeg|gif|webp|svg)$ {
        proxy_pass http://backend;
        proxy_set_header Host $host;

        # Only cache if not authenticated AND content type is static
        proxy_no_cache $is_authenticated;
        proxy_cache_bypass $is_authenticated;

        # Cache key includes Content-Type to prevent deception
        proxy_cache_key "$scheme$request_method$host$request_uri$http_accept";

        proxy_cache static_cache;
        proxy_cache_valid 200 301 302 365d;
        proxy_cache_use_stale error timeout updating;

        # Always set nosniff
        add_header X-Content-Type-Options nosniff;
    }

    # Sensitive pages - never cache
    location ~* ^/(account|profile|settings|api|auth|login|checkout|payment) {
        proxy_pass http://backend;
        proxy_set_header Host $host;

        # Explicitly disable caching
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma no-cache;
        add_header Expires 0;

        # Prevent CDN from caching
        proxy_no_cache 1;
        proxy_cache_bypass 1;
    }

    # Default: don't cache
    location / {
        proxy_pass http://backend;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
    }
}
"""


# ========== Usage Example ==========
if __name__ == "__main__":
    middleware = CDNMiddleware()

    # Attack scenario: attacker tricks user into visiting:
    # /account/settings/nonexistent.css
    # Without fix: CDN caches this as .css, exposing session data
    # With fix: CDN refuses to cache because it's an authenticated path

    test_cases = [
        ("/assets/style.css", "text/css", False),      # Should cache
        ("/account/settings/nonexistent.css", "text/css", True),  # Should NOT cache
        ("/assets/app.js", "text/javascript", False),   # Should cache
        ("/api/user/data", "application/json", True),   # Should NOT cache
        ("/assets/image.png", "image/png", False),      # Should cache
        ("/profile/update", "text/html", True),         # Should NOT cache
    ]

    for path, content_type, is_auth in test_cases:
        headers = middleware.process_response(path, content_type, is_auth)
        print(f"Path: {path:45} | Auth: {is_auth}")
        print(f"  Headers: {headers}")
        print()
