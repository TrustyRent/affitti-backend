# app/routers/auth.py
from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Header,
    Body,
    Query,
    Request,
    Response,
    Depends,
)
from pydantic import BaseModel, EmailStr, Field

from app.core.security import require_admin  # protezione admin

router = APIRouter()

# ====== Config ======
SUPABASE_URL = os.getenv("SUPABASE_URL")
ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not ANON_KEY or not SERVICE_ROLE:
    raise RuntimeError("Config mancante: SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY")

# Cookie/env per refresh
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "refresh_token")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"   # True in prod (HTTPS)
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")                   # "lax" o "none"
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN")                              # es. ".tuodominio.it"
COOKIE_PATH = "/auth"                                                   # restringe il path
REFRESH_MAX_AGE = int(os.getenv("REFRESH_MAX_AGE", str(60 * 60 * 24 * 7)))  # 7 giorni default

# ====== Helpers ======
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
        raise HTTPException(status_code=400, detail=f"Auth admin search failed: {r.text}")
    data = r.json()
    users = data.get("users") if isinstance(data, dict) else data
    return (users or [None])[0]

def _set_refresh_cookie(response: Response, refresh_token: str):
    # Se SameSite=None, lo standard richiede Secure=True
    samesite = COOKIE_SAMESITE
    secure = COOKIE_SECURE or (samesite.lower() == "none")

    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=secure,
        samesite=samesite,   # 'none' o 'lax'
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
        max_age=REFRESH_MAX_AGE,
    )

def _clear_refresh_cookie(response: Response):
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
    )

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")

def normalize_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9_]", "_", u)
    u = re.sub(r"_+", "_", u)
    return u

def norm_email(e: str) -> str:
    return (e or "").strip().lower()

# ====== Schemi ======
class RegisterIn(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=100)
    last_name:  str = Field(..., min_length=2, max_length=100)
    username:   str = Field(..., min_length=3, max_length=50)
    email:      EmailStr
    password:   str = Field(..., min_length=8, max_length=256)

class RegisterOut(BaseModel):
    id: str
    email: EmailStr

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    # mantenuto per retro-compatibilità ma il frontend NON deve più usarlo
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

# ====== Endpoints ======
@router.post("/register", response_model=RegisterOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn):
    uname = normalize_username(payload.username)
    if not USERNAME_RE.fullmatch(uname):
        raise HTTPException(status_code=422, detail="Username non valido. Usa 3-30 caratteri: minuscole, numeri e underscore.")

    email = norm_email(str(payload.email))

    # 1) Crea utente Auth (email confermata)
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
            try:
                j = resp.json()
                txt += f" {str(j).lower()}"
            except Exception:
                pass
            if "already registered" in txt:
                raise HTTPException(status_code=409, detail="Email già registrata. Esegui il login o resetta la password.")
            raise HTTPException(status_code=400, detail=f"Auth create failed: {resp.text}")

        body = resp.json()
        user_id = body.get("user", {}).get("id")
        if not user_id:
            created = _get_user_by_email(email, timeout=6)
            if not created:
                raise HTTPException(status_code=500, detail="Auth user non reperibile dopo la creazione")
            user_id = created["id"]
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Auth admin error: {e}")

    # 2) Inserisci/Merge profilo
    profile = {
        "id": user_id,
        "nome": payload.first_name,
        "username": uname,
        "email": email,
        "is_active": True,
        "role": "user",
        "token_version": 0,
    }
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/utenti",
            headers={
                "apikey": SERVICE_ROLE,
                "Authorization": f"Bearer {SERVICE_ROLE}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
            json=profile,
            timeout=8,
        )
        if r.status_code not in (200, 201, 204):
            raise HTTPException(status_code=400, detail=f"Insert profilo failed: {r.text}")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"DB REST error: {e}")

    return RegisterOut(id=user_id, email=email)

@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, response: Response):
    """Password grant verso Supabase; setta refresh in cookie HttpOnly."""
    email = norm_email(str(payload.email))
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers=_anon_headers(),
            json={"email": email, "password": payload.password},
            timeout=10,
        )
        if resp.status_code != 200:
            msg = "Email o password non valide"
            try:
                j = resp.json()
                msg = j.get("error_description") or j.get("message") or msg
            except Exception:
                pass
            raise HTTPException(status_code=401, detail=msg)

        body = resp.json()
        access = body["access_token"]
        refresh = body["refresh_token"]
        expires_in = body.get("expires_in")  # secondi

        # Imposta cookie HttpOnly col refresh (browser lo invia sempre)
        _set_refresh_cookie(response, refresh)

        # Ritorniamo access + expires_in; refresh_token nel body solo per retro-compatibilità
        return TokenOut(
            access_token=access,
            refresh_token=refresh,   # DEPRECATO lato client
            expires_in=expires_in,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Login error: {e}")

@router.post("/refresh", response_model=TokenOut)
def refresh(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Body(default=None, embed=True),
):
    """
    Rigenera access token usando refresh:
    - se presente nel body lo usa (retro-compatibilità),
    - altrimenti legge dal cookie HttpOnly e **ruota** il refresh nel cookie.
    """
    token = refresh_token or request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token mancante")

    try:
        resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers=_anon_headers(),
            json={"refresh_token": token},
            timeout=10,
        )
        if resp.status_code != 200:
            msg = "Refresh token non valido"
            try:
                j = resp.json()
                msg = j.get("error_description") or j.get("message") or msg
            except Exception:
                pass
            raise HTTPException(status_code=401, detail=msg)

        body = resp.json()
        access = body["access_token"]
        new_refresh = body.get("refresh_token")  # Supabase in genere ruota
        expires_in = body.get("expires_in")

        if new_refresh:
            _set_refresh_cookie(response, new_refresh)

        return TokenOut(
            access_token=access,
            refresh_token=new_refresh,  # DEPRECATO lato client
            expires_in=expires_in,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Refresh error: {e}")

@router.get("/me")
def me(authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token mancante")
    token = authorization.split(" ", 1)[1]
    try:
        r = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={"Authorization": f"Bearer {token}", "apikey": ANON_KEY},
            timeout=8,
        )
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Token non valido")
        return r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Me error: {e}")

@router.post("/logout")
def logout(response: Response):
    _clear_refresh_cookie(response)
    return {"ok": True, "ts": int(time.time())}

# --- Forgot/Reset password ---
@router.post("/forgot")
def forgot_password(body: ForgotIn):
    redirect_to = os.getenv("FRONTEND_RESET_URL", "http://localhost:3000/reset")
    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/recover",
        headers={"apikey": ANON_KEY, "Authorization": f"Bearer {ANON_KEY}", "Content-Type": "application/json"},
        json={"email": str(body.email).strip().lower(), "redirect_to": redirect_to},
        timeout=10,
    )
    if r.status_code not in (200, 204):
        try:
            msg = r.json().get("error_description") or r.text
        except Exception:
            msg = r.text
        raise HTTPException(status_code=400, detail=msg)
    return {"ok": True}

@router.post("/reset")
def reset_password(body: ResetIn, authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token di recovery mancante")
    token = authorization.split(" ", 1)[1]

    r = requests.put(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={"apikey": ANON_KEY, "Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"password": body.new_password},
        timeout=10,
    )
    if r.status_code != 200:
        try:
            msg = r.json().get("error_description") or r.text
        except Exception:
            msg = r.text
        raise HTTPException(status_code=400, detail=msg)
    return {"ok": True}

# ====== ADMIN / DEBUG ======
@router.get("/admin/lookup-user", dependencies=[Depends(require_admin)])
def admin_lookup_user(email: EmailStr = Query(...)):
    u = _get_user_by_email(norm_email(str(email)), timeout=6)
    return {"exists": bool(u), "user_id": (u or {}).get("id")}

@router.post("/admin/set-password", dependencies=[Depends(require_admin)])
def admin_set_password(body: SetPasswordIn):
    email = norm_email(str(body.email))
    u = _get_user_by_email(email, timeout=6)
    if not u:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    uid = u["id"]

    r = requests.put(
        f"{SUPABASE_URL}/auth/v1/admin/users/{uid}",
        headers=_admin_headers(),
        json={
            "password": body.new_password,
            "email_confirm": True,
            "email_confirmed_at": datetime.now(timezone.utc).isoformat(),
        },
        timeout=8,
    )
    if r.status_code >= 300:
        raise HTTPException(status_code=400, detail=f"Update failed: {r.text}")
    return {"ok": True, "user_id": uid}

@router.get("/debug/env", dependencies=[Depends(require_admin)])
def debug_env():
    def mask(k: str) -> str:
        return f"{k[:6]}...{k[-6:]}" if isinstance(k, str) and len(k) > 12 else "invalid"
    return {
        "supabase_url": SUPABASE_URL,
        "anon_key": mask(ANON_KEY),
        "service_role_key": mask(SERVICE_ROLE),
    }

@router.post("/admin/_raw_login_debug", dependencies=[Depends(require_admin)])
def admin_raw_login_debug(body: LoginIn):
    url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": ANON_KEY,
        "Authorization": f"Bearer {ANON_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"email": str(body.email).strip().lower(), "password": body.password}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=10)
        try:
            body_json = r.json()
        except Exception:
            body_json = None
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "json": body_json,
            "text": None if body_json is not None else r.text,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase call failed: {e}")
