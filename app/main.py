from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarHTTP
import os

from app.routers import auth, utenti, locatari
from app.core.logging import AccessLogMiddleware  # step 1

app = FastAPI(title="Affitti API")
app.add_middleware(AccessLogMiddleware)  # step 1

# === CORS ===
FRONTEND_PROD = os.getenv("FRONTEND_PROD", "https://trusty-rent.vercel.app")
origins = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:13000",
    "http://localhost:13000",
    FRONTEND_PROD,  # produzione (domain esplicito)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,                       # origini specifiche
    allow_origin_regex=r"https://.*\.vercel\.app$",  # TUTTI i *.vercel.app (preview + prod)
    allow_credentials=True,  # cookie HttpOnly
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Error handlers uniformi ----------
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
# ---------------------------------------------

# Routers
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(utenti.router, prefix="/utenti", tags=["Utenti"])
app.include_router(locatari.router)  # ha già prefix="/locatari"

# Health & root
@app.get("/")
def root():
    return {"ok": True, "service": "Affitti API"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/ping")
def ping():
    return {"status": "ok"}
