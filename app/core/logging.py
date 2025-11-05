# app/core/logging.py
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        start = time.perf_counter()
        response = await call_next(request)
        dur_ms = int((time.perf_counter() - start) * 1000)

        # aggiungo l'id nella risposta
        response.headers["X-Request-ID"] = rid

        # log compatto
        method = request.method
        path = request.url.path
        status = response.status_code
        print(f"[{rid}] {method} {path} -> {status} {dur_ms}ms")

        return response
