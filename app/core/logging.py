# app/core/logging.py
from __future__ import annotations
import time
from typing import Callable
from starlette.types import ASGIApp, Receive, Scope, Send

class AccessLogMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method")
        path = scope.get("path")
        start = time.perf_counter()
        status_holder = {"code": 200}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            dur_ms = int((time.perf_counter() - start) * 1000)
            # Log minimale su stdout (Render / Railway lo raccolgono)
            print(f"[ACCESS] {method} {path} -> {status_holder['code']} ({dur_ms}ms)")
