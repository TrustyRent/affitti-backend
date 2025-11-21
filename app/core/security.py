# app/core/security.py
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, Request, Header, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
import requests

# --- Config base ---
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

# Nomi cookie (allineati a auth.py)
ACCESS_COOKIE_NAME = os.getenv("ACCESS_COOKIE_NAME", "access_token")
ALT_ACCESS_NAMES = [
    ACCESS_COOKIE_NAME,
    "sb-access-token",
    "accessToken",
    "sb-accessToken",
]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_minutes: int = 30) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    if not SUPABASE_JWT_SECRET:
        raise RuntimeError("SUPABASE_JWT_SECRET mancante: token locale non generabile.")
    return jwt.encode(to_encode, SUPABASE_JWT_SECRET, algorithm=JWT_ALG)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def _verify_with_local_secret(token: str) -> Optional[Dict[str, Any]]:
    if not SUPABASE_JWT_SECRET:
        return None
    try:
        payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except JWTError:
        return None


def _verify_with_supabase_user_endpoint(token: str) -> Optional[Dict[str, Any]]:
    if not (SUPABASE_URL and SUPABASE_ANON_KEY):
        return None
    try:
        r = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {token}"},
            timeout=8,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def get_current_subject(
    request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> str:
    token: Optional[str] = None

    # 1) Token da Authorization: Bearer ...
    if creds and creds.scheme.lower() == "bearer":
        token = creds.credentials

    # 2) Se non c'è, prova dai cookie (stessi nomi che usiamo in auth.py)
    if not token:
        cookies = request.cookies or {}
        for name in ALT_ACCESS_NAMES:
            val = cookies.get(name)
            if val:
                token = val
                break

    if not token:
        raise HTTPException(status_code=401, detail="Token mancante")

    # 3) Prima prova a decodificare con la secret locale (se configurata)
    payload = _verify_with_local_secret(token)
    if payload:
        sub = payload.get("sub") or payload.get("user_id") or payload.get("id")
        if sub:
            return str(sub)

    # 4) Fallback: chiedi direttamente a Supabase se il token è valido
    info = _verify_with_supabase_user_endpoint(token)
    if info and isinstance(info, dict):
        sub = info.get("id") or info.get("user", {}).get("id")
        if sub:
            return str(sub)

    raise HTTPException(status_code=401, detail="Token non valido o scaduto")


def get_current_user(
    request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Dict[str, Any]:
    uid = get_current_subject(request, creds)
    return {"id": uid}


# --------- Dipendenza riutilizzabile per rotte admin ---------
def _headers_user(bearer: str) -> Dict[str, str]:
    return {"apikey": SUPABASE_ANON_KEY or "", "Authorization": bearer, "Content-Type": "application/json"}


def _headers_service() -> Dict[str, str]:
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        raise HTTPException(status_code=500, detail="Service role non configurato")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def require_admin(authorization: str = Header(default="")) -> None:
    """
    Usa dependencies=[Depends(require_admin)] sulla rotta da proteggere.
    1) Valida il token via /auth/v1/user
    2) Verifica role='admin' nella tabella 'utenti' (REST con service role)
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token mancante")

    # 1) Valida token e prendi uid
    try:
        r = requests.get(f"{SUPABASE_URL}/auth/v1/user", headers=_headers_user(authorization), timeout=8)
    except Exception:
        raise HTTPException(status_code=502, detail="Errore contattando Supabase auth")
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Token non valido o scaduto")
    uid = r.json().get("id")

    # 2) Controllo ruolo
    try:
        r2 = requests.get(
            f"{SUPABASE_URL}/rest/v1/utenti",
            headers=_headers_service(),
            params={"select": "role", "id": f"eq.{uid}", "limit": 1},
            timeout=8,
        )
    except Exception:
        raise HTTPException(status_code=502, detail="Errore contattando Supabase DB")
    if r2.status_code != 200:
        raise HTTPException(status_code=500, detail=r2.text)
    data = r2.json()
    role = (data[0] or {}).get("role") if data else None
    if role != "admin":
        raise HTTPException(status_code=403, detail="Permessi admin richiesti")
