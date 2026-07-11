# [BUG] CORS Misconfiguration + Origin Reflection → Credential Theft — Fix

## Issue #955

### Vulnerability
API reflects `Access-Control-Allow-Origin: {Origin}` from the request header with `Access-Control-Allow-Credentials: true`. Any website can make credentialed cross-origin requests and read API responses.

### Fix Implementation

```python
# Before (vulnerable):
@app.middleware("http")
async def cors_middleware(request, call_next):
    origin = request.headers.get("origin", "*")
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# After (secure):
ALLOWED_ORIGINS = {
    "https://example.com",
    "https://www.example.com",
    "https://app.example.com",
}

@app.middleware("http")
async def cors_middleware(request, call_next):
    origin = request.headers.get("origin", "")
    response = await call_next(request)
    
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        # No CORS headers for untrusted origins
        response.headers["Access-Control-Allow-Origin"] = ""
    
    response.headers["Vary"] = "Origin"
    return response
```

### FastAPI-specific Implementation

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

# Whitelist-based CORS (replaces wildcard config)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://example.com",
        "https://www.example.com",
        "https://app.example.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
```

### Express.js Implementation (Node.js)

```javascript
const ALLOWED_ORIGINS = [
  'https://example.com',
  'https://www.example.com',
  'https://app.example.com',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  // No CORS headers for untrusted origins
  
  res.setHeader('Vary', 'Origin');
  next();
});
```

### Verification Checklist
- [x] Origin whitelist validation implemented
- [x] No wildcard `*` in `Access-Control-Allow-Origin` when credentials=true
- [x] `Vary: Origin` header returned in all responses
- [x] Untrusted origins receive no CORS headers
- [x] Credentials + wildcard combination eliminated

### Security Impact
- **Before**: `Access-Control-Allow-Origin: https://attacker.com` + `credentials: true` → credential theft
- **After**: Only whitelisted origins receive CORS headers; attacker domains blocked
