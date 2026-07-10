# Nginx Security Configuration

## HTTP/2-Only Listener

This configuration prevents HTTP/2 → HTTP/1.1 downgrade request smuggling.

### Deployment

```bash
# Copy config
sudo cp http2-only.conf /etc/nginx/sites-available/api.example.com
sudo ln -s /etc/nginx/sites-available/api.example.com /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Reload
sudo systemctl reload nginx
```

### Testing

```bash
# HTTP/2 should work
curl --http2 -k https://localhost:443/api

# HTTP/1.1 should be rejected
curl --http1.1 -k https://localhost:443/api
# → 426 Upgrade Required

# Missing :authority should be rejected
curl --http2 -k -H "Host: example.com" https://localhost:443/api
# → 400 Bad Request
```

### Security Headers
All responses include:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000`
