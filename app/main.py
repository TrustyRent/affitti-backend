# app/main.py
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarHTTP
import os
import re

# === Router esistenti ===
from app.routers import auth, utenti, locatari

# Access log middleware (ora presente)
try:
    from app.core.logging import AccessLogMiddleware
except Exception:
    AccessLogMiddleware = None

# Rate limit middleware (agganciato)
try:
    from app.middlewares.rate_limit import rate_limit_middleware
except Exception:
    rate_limit_middleware = None

app = FastAPI(title="Affitti API")

if AccessLogMiddleware:
    app.add_middleware(AccessLogMiddleware)

# ============= CORS =============
FRONTEND_PROD = os.getenv("FRONTEND_PROD", "https://trusty-rent.vercel.app")

ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    FRONTEND_PROD.rstrip("/"),
}

VERCEL_RE = re.compile(r"^https://[a-z0-9-]+\.vercel\.app$", re.IGNORECASE)

def origin_allowed(origin: str | None) -> bool:
    if not origin:
        return False
    o = origin.rstrip("/")
    if o in ALLOWED_ORIGINS:
        return True
    if VERCEL_RE.match(o):
        return True
    return False

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_origin_regex=r"https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
    max_age=86400,
)

# Aggancio **rate limit** a livello globale (se disponibile)
if rate_limit_middleware:
    app.middleware("http")(rate_limit_middleware)

# ===== OPTIONS Catch-All (preflight) =====
@app.options("/{full_path:path}")
async def any_options(full_path: str, request: Request) -> Response:
    origin = request.headers.get("origin")
    if not origin_allowed(origin):
        return PlainTextResponse("Origin not allowed", status_code=400)
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Vary": "Origin",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": request.headers.get(
            "access-control-request-headers", "*"
        ) or "*",
        "Access-Control-Max-Age": "86400",
    }
    return Response(status_code=204, headers=headers)

# ===== Error handlers =====
@app.exception_handler(StarHTTP)
async def http_exception_handler(_, exc: StarHTTP):
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.status_code, "message": str(exc.detail)},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"code": 422, "message": "Validation error", "errors": exc.errors()},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(_, exc: Exception):
    print("UNHANDLED ERROR:", repr(exc))
    return JSONResponse(
        status_code=500,
        content={"code": 500, "message": "Internal server error"},
    )

# ===== Routers =====
app.include_router(auth.router,     prefix="/auth",   tags=["Auth"])
app.include_router(utenti.router,   prefix="/utenti", tags=["Utenti"])
app.include_router(locatari.router)  # ha già prefix /locatari

# ===== Health =====
@app.get("/")
def root():
    return {"ok": True, "service": "Affitti API"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/ping")
def ping():
    return {"status": "ok"}
