# app/middlewares/rate_limit.py
import os
import time
from fastapi import Request, HTTPException
from typing import Dict, Tuple

# (ip, route) -> (reset_ts, count)
_BUCKETS: Dict[Tuple[str, str], Tuple[float, int]] = {}

WINDOW_SEC = int(os.getenv("RL_WINDOW_SEC", "60"))
MAX_REQ = int(os.getenv("RL_MAX_REQ", "10"))
PROTECTED_PATHS = set(
    (p.strip() for p in os.getenv("RL_PATHS", "/auth/login,/auth/register,/auth/forgot").split(","))
)

async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if not any(path.startswith(p) for p in PROTECTED_PATHS):
        return await call_next(request)

    ip = request.client.host if request.client else "unknown"
    key = (ip, path)
    now = time.time()
    reset, count = _BUCKETS.get(key, (now + WINDOW_SEC, 0))

    if now > reset:
        reset, count = now + WINDOW_SEC, 0

    count += 1
    _BUCKETS[key] = (reset, count)

    if count > MAX_REQ:
        raise HTTPException(status_code=429, detail=f"Too many requests. Retry after {int(reset - now)}s")

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(MAX_REQ)
    response.headers["X-RateLimit-Remaining"] = str(max(0, MAX_REQ - count))
    response.headers["X-RateLimit-Reset"] = str(int(reset))
    return response
