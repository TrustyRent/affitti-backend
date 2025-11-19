# app/routers/auth.py
from __future__ import annotations

import os
import re
import time
from typing import Optional, Dict, Any

import requests
from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Header,
    Request,
    Response,
    Cookie,
)
from pydantic import BaseModel, EmailStr, Field

# se avevi un require_admin lo manteniamo
try:
    from app.core.security import require_admin
except Exception:
    def require_admin():
        return True

router = APIRouter()

# ====== Config ======
SUPABASE_URL = os.getenv("SUPABASE_URL")
ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
if not SUPABASE_URL or not ANON_KEY or not SERVICE_ROLE:
    raise RuntimeError(
        "Config mancante: SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY"
    )

# Nomi cookie
ACCESS_COOKIE = os.getenv("ACCESS_COOKIE_NAME", "access_token")
REFRESH_COOKIE = os.getenv("REFRESH_COOKIE_NAME", "refresh_token")

# Ambiente (dev / prod) per gestire i cookie in modo sicuro ma senza impazzire in locale
_ENV_RAW = (os.getenv("ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
IS_LOCAL_ENV = _ENV_RAW in {"dev", "development", "local", "debug"}

_raw_samesite = (os.getenv("COOKIE_SAMESITE", "none") or "none").strip().lower()
COOKIE_SAMESITE = (
    _raw_samesite if _raw_samesite in {"lax", "strict", "none"} else "none"
)

COOKIE_SECURE = (os.getenv("COOKIE_SECURE", "true") or "true").strip().lower() == "true"
COOKIE_HTTPONLY = True
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN") or None
COOKIE_PATH = "/"

# Se siamo in locale forziamo impostazioni più permissive per far funzionare tutto
if IS_LOCAL_ENV:
    # In dev vogliamo che i cookie funzionino anche in http e con porte diverse
    COOKIE_SAMESITE = "lax"
    COOKIE_SECURE = False
    COOKIE_DOMAIN = None
else:
    # In produzione, se usi SameSite=None DEVE essere Secure
    if COOKIE_SAMESITE == "none":
        COOKIE_SECURE = True

ACCESS_MAX_AGE = int(os.getenv("ACCESS_MAX_AGE", str(60 * 15)))  # 15 min
REFRESH_MAX_AGE = int(
    os.getenv("REFRESH_MAX_AGE", str(60 * 60 * 24 * 7))
)  # 7 giorni


# ===== Helpers comuni =====
def _admin_headers() -> dict[str, str]:
    return {
        "apikey": SERVICE_ROLE,
        "Authorization": f"Bearer {SERVICE_ROLE}",
        "Content-Type": "application/json",
    }


def _anon_headers() -> dict[str, str]:
    return {
        "apikey": ANON_KEY,
        "Authorization": f"Bearer {ANON_KEY}",
        "Content-Type": "application/json",
    }


def _get_user_by_email(email: str, timeout: int = 8) -> Optional[dict]:
    r = requests.get(
        f"{SUPABASE_URL}/auth/v1/admin/users",
        headers=_admin_headers(),
        params={"email": email},
        timeout=timeout,
    )
    if r.status_code >= 300:
        raise HTTPException(
            status_code=400, detail=f"Auth admin search failed: {r.text}"
        )
    data = r.json()
    users = data.get("users") if isinstance(data, dict) else data
    return (users or [None])[0]


def _set_cookie(resp: Response, key: str, val: str, max_age: int) -> None:
    resp.set_cookie(
        key=key,
        value=val,
        max_age=max_age,
        path=COOKIE_PATH,
        secure=COOKIE_SECURE,
        httponly=COOKIE_HTTPONLY,
        samesite=COOKIE_SAMESITE,
        domain=COOKIE_DOMAIN,
    )


def _del_cookie(resp: Response, key: str) -> None:
    resp.delete_cookie(key=key, path=COOKIE_PATH, domain=COOKIE_DOMAIN)


USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")


def normalize_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9_]", "_", u)
    u = re.sub(r"_+", "_", u)
    return u


def norm_email(e: str) -> str:
    return (e or "").strip().lower()


# ==== Schemi ====
class RegisterIn(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=100)
    last_name: str = Field(..., min_length=2, max_length=100)
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class RegisterOut(BaseModel):
    id: str
    email: EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None


class SetPasswordIn(BaseModel):
    email: EmailStr
    new_password: str = Field(..., min_length=8, max_length=256)


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=256)


# ==== Cookie pickers ====
ALT_ACCESS_NAMES = [ACCESS_COOKIE, "sb-access-token", "accessToken", "sb-accessToken"]
ALT_REFRESH_NAMES = [
    REFRESH_COOKIE,
    "sb-refresh-token",
    "refreshToken",
    "sb-refreshToken",
]


def pick_access(req: Request, authorization: str) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()

    for k in ALT_ACCESS_NAMES:
        v = (req.cookies or {}).get(k)
        if v:
            return v
    return None


def pick_refresh(req: Request) -> Optional[str]:
    for k in ALT_REFRESH_NAMES:
        v = (req.cookies or {}).get(k)
        if v:
            return v
    return None


# ====== Endpoints ======


@router.post(
    "/register",
    response_model=RegisterOut,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterIn):
    uname = normalize_username(payload.username)
    if not USERNAME_RE.fullmatch(uname):
        raise HTTPException(
            status_code=422,
            detail=(
                "Username non valido. "
                "Usa 3-30 caratteri minuscoli, numeri e underscore."
            ),
        )
    email = norm_email(str(payload.email))

    # 1) Crea utente Auth
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/admin/users",
            headers=_admin_headers(),
            json={
                "email": email,
                "password": payload.password,
                "email_confirm": True,
                "user_metadata": {
                    "username": uname,
                    "first_name": payload.first_name,
                    "last_name": payload.last_name,
                },
            },
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            txt = (resp.text or "").lower()
            if "already registered" in txt:
                raise HTTPException(status_code=409, detail="Email già registrata.")
            raise HTTPException(
                status_code=400, detail=f"Auth create failed: {resp.text}"
            )
        user_id = resp.json().get("user", {}).get("id")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Auth admin error: {e}")

    # 2) Inserisci profilo DB
    profile = {
        "id": user_id,
        "nome": payload.first_name,
        "username": uname,
        "email": email,
        "is_active": True,
        "role": "user",
        "token_version": 0,
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/utenti",
        headers=_admin_headers(),
        json=profile,
        timeout=8,
    )
    if r.status_code not in (200, 201, 204):
        raise HTTPException(status_code=400, detail=f"Insert profilo failed: {r.text}")

    return RegisterOut(id=user_id, email=email)


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, response: Response):
    email = norm_email(str(payload.email))
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers=_anon_headers(),
            json={"email": email, "password": payload.password},
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Email o password non valide")
        body = resp.json()
        access = body["access_token"]
        refresh = body["refresh_token"]
        expires_in = body.get("expires_in")

        # Cookie per access e refresh
        _set_cookie(response, ACCESS_COOKIE, access, ACCESS_MAX_AGE)
        _set_cookie(response, REFRESH_COOKIE, refresh, REFRESH_MAX_AGE)

        return TokenOut(
            access_token=access,
            refresh_token=refresh,
            expires_in=expires_in,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Login error: {e}")


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, response: Response, body: Dict[str, Any] | None = None):
    explicit = body.get("refresh_token") if body else None
    token = explicit or pick_refresh(request)
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token mancante")

    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
        headers=_anon_headers(),
        json={"refresh_token": token},
        timeout=10,
    )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Refresh non valido")

    data = r.json()
    new_access = data["access_token"]
    new_refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")

    _set_cookie(response, ACCESS_COOKIE, new_access, ACCESS_MAX_AGE)
    if new_refresh:
        _set_cookie(response, REFRESH_COOKIE, new_refresh, REFRESH_MAX_AGE)

    return TokenOut(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=expires_in,
    )


@router.get("/me")
def me(
    request: Request,
    response: Response,
    authorization: str = Header(default=""),
    access_cookie: Optional[str] = Cookie(default=None, alias=ACCESS_COOKIE),
):
    """
    Restituisce l'utente corrente.
    - Prima prova con access_token (header/cookie)
    - Se manca ma c'è un refresh_token, fa il refresh al volo,
      aggiorna i cookie e poi legge l'utente.
    """
    # 1) Prova a prendere l'access token
    token = pick_access(request, authorization) or access_cookie

    # 2) Se non c'è access ma abbiamo un refresh → refresh automatico
    if not token:
        refresh_token = pick_refresh(request)
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Token mancante")

        r = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers=_anon_headers(),
            json={"refresh_token": refresh_token},
            timeout=8,
        )
        if r.status_code != 200:
            # refresh fallito → consideriamo il token non valido
            raise HTTPException(status_code=401, detail="Token non valido")

        data = r.json()
        token = data["access_token"]
        new_refresh = data.get("refresh_token")

        # aggiorna cookie access + refresh
        _set_cookie(response, ACCESS_COOKIE, token, ACCESS_MAX_AGE)
        if new_refresh:
            _set_cookie(response, REFRESH_COOKIE, new_refresh, REFRESH_MAX_AGE)

    # 3) A questo punto abbiamo sicuramente un access token → chiamiamo /auth/v1/user
    r = requests.get(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={"Authorization": f"Bearer {token}", "apikey": ANON_KEY},
        timeout=8,
    )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Token non valido")

    return r.json()


@router.post("/logout")
def logout(response: Response):
    _del_cookie(response, ACCESS_COOKIE)
    _del_cookie(response, REFRESH_COOKIE)
    return {"ok": True, "ts": int(time.time())}
