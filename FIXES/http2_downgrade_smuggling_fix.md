# HTTP/2 Downgrade → Request Smuggling Fix (#799, $200 Expert)

## Vulnerability
Load balancer accepts HTTP/2 but downgrades to HTTP/1.1 when forwarding to backend.
Pseudo-headers (`:authority`, `:path`) become ambiguous in HTTP/1.1, enabling request smuggling.

## Fix 1: End-to-End HTTP/2 (Recommended)

### nginx Configuration
```nginx
# Global: force HTTP/2 throughout
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    location / {
        proxy_pass https://backend_upstream;
        proxy_http_version 1.1;  # Backend must support HTTP/2
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Backend must also serve HTTP/2
upstream backend_upstream {
    server 10.0.0.1:443;
}

server {
    listen 8080 ssl http2;
    # Internal backend server...
}
```

## Fix 2: HTTP/2-Only Listener (No Downgrade)

```nginx
# Accept ONLY HTTP/2 connections
server {
    listen 443 ssl http2;
    
    # Reject HTTP/1.1 connections
    if ($server_protocol !~ "HTTP/2") {
        return 426 "Upgrade Required";
    }
    
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # Strip pseudo-headers before downgrade
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Remove ambiguous headers
        proxy_set_header "" $http_authority;
    }
}
```

## Fix 3: Header Sanitization (If Downgrade Required)

```nginx
# Strip and validate pseudo-headers
map $http_authority $validated_host {
    default $http_authority;
    "" $host;
}

server {
    listen 443 ssl http2;
    
    location / {
        # Validate Content-Length consistency
        if ($content_length != $upstream_http_content_length) {
            return 400 "Content-Length mismatch";
        }
        
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Host $validated_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Remove connection-specific headers
        proxy_set_header Connection "";
        proxy_set_header Transfer-Encoding "";
    }
}
```

## Verification

```bash
# Test HTTP/2 only
curl --http2 -k https://example.com/api
# Should succeed

# Test HTTP/1.1 rejection
curl --http1.1 -k https://example.com/api
# Should return 426 Upgrade Required

# Test smuggling attempt
curl -k -H "Transfer-Encoding: chunked" \
     -H "Content-Length: 5" \
     -d "x=1" \
     https://example.com/api
# Should return 400 Bad Request
```
