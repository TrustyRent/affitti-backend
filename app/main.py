from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarHTTP

from app.routers import auth, utenti, locatari
from app.core.logging import AccessLogMiddleware  # step 1

app = FastAPI(title="Affitti API")
app.add_middleware(AccessLogMiddleware)  # step 1

origins = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:13000",
    "http://localhost:13000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,  # cookie HttpOnly
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Error handlers uniformi ----------
@app.exception_handler(StarHTTP)
async def http_exception_handler(_, exc: StarHTTP):
    # es. raise HTTPException(status_code=401, detail="Token non valido")
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.status_code, "message": str(exc.detail)},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError):
    # errori di validazione Pydantic/FastAPI (422)
    return JSONResponse(
        status_code=422,
        content={"code": 422, "message": "Validation error", "errors": exc.errors()},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(_, exc: Exception):
    # fallback: non mostra stacktrace all'utente, ma logga in console
    print("UNHANDLED ERROR:", repr(exc))
    return JSONResponse(
        status_code=500,
        content={"code": 500, "message": "Internal server error"},
    )
# ---------------------------------------------

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(utenti.router, prefix="/utenti", tags=["Utenti"])
app.include_router(locatari.router)  # ha già prefix="/locatari"

@app.get("/")
def root():
    return {"ok": True, "service": "Affitti API"}

@app.get("/health")
def health():
    return {"status": "ok"}
