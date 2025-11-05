# app/routers/utenti.py
from __future__ import annotations

import os, re, requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel, EmailStr, Field, validator

SUPABASE_URL = os.getenv("SUPABASE_URL")
SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
if not SUPABASE_URL or not SERVICE_ROLE:
    raise RuntimeError("Config mancante: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY")

router = APIRouter()
TABLE = "utenti"

from app.core.emailer import notify_admin_new_signup, notify_user_decision

def _admin_headers(extra: Dict[str, str] | None = None) -> Dict[str, str]:
    base = {"apikey": SERVICE_ROLE, "Authorization": f"Bearer {SERVICE_ROLE}", "Content-Type": "application/json"}
    if extra: base.update(extra)
    return base

def _user_headers(bearer: str) -> Dict[str, str]:
    return {"apikey": SERVICE_ROLE, "Authorization": bearer, "Content-Type": "application/json"}

def require_bearer(authorization: str = Header(default="")) -> str:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token mancante")
    return authorization

def get_auth_user(authorization: str = Depends(require_bearer)) -> Dict[str, Any]:
    try:
        r = requests.get(f"{SUPABASE_URL}/auth/v1/user", headers=_user_headers(authorization), timeout=15)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Token non valido o scaduto")
        return r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Auth error: {e}")

def _require_admin(auth_user: Dict[str, Any] = Depends(get_auth_user)) -> Dict[str, Any]:
    uid = auth_user.get("id")
    r = requests.get(f"{SUPABASE_URL}/rest/v1/{TABLE}",
                     headers=_admin_headers(), params={"select": "role", "id": f"eq.{uid}", "limit": 1}, timeout=10)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=r.text)
    data = r.json()
    role = (data[0] or {}).get("role") if data else None
    if role != "admin":
        raise HTTPException(status_code=403, detail="Permessi admin richiesti")
    return auth_user

def _require_approved_user(auth_user: Dict[str, Any] = Depends(get_auth_user)) -> Dict[str, Any]:
    uid = auth_user.get("id")
    r = requests.get(f"{SUPABASE_URL}/rest/v1/{TABLE}",
                     headers=_admin_headers(), params={"select": "stato", "id": f"eq.{uid}", "limit": 1}, timeout=10)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=r.text)
    data = r.json()
    stato = (data[0] or {}).get("stato") if data else None
    if stato != "approved":
        raise HTTPException(status_code=403, detail="Account in attesa di approvazione")
    return auth_user

class UtenteOut(BaseModel):
    id: Optional[str] = None
    nome: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None
    tipo: Optional[str] = None
    codice_fiscale: Optional[str] = None
    partita_iva: Optional[str] = None
    ragione_sociale: Optional[str] = None
    stato: Optional[str] = None
    motivo_rifiuto: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

UtentiOut = List[UtenteOut]
_CF_RE = re.compile(r"^[A-Z0-9]{16}$", re.IGNORECASE)
_PIVA_RE = re.compile(r"^[0-9]{11}$")

class RegistrazionePrivato(BaseModel):
    email: EmailStr
    nome: Optional[str] = None
    username: Optional[str] = None
    codice_fiscale: str = Field(..., description="Codice fiscale (16 caratteri)")
    @validator("codice_fiscale")
    def _check_cf(cls, v):
        v = v.strip().upper()
        if not _CF_RE.match(v):
            raise ValueError("Codice fiscale non valido")
        return v

class RegistrazioneAzienda(BaseModel):
    email: EmailStr
    nome: Optional[str] = None
    username: Optional[str] = None
    partita_iva: str = Field(..., description="Partita IVA (11 cifre)")
    ragione_sociale: str = Field(..., min_length=2)
    @validator("partita_iva")
    def _check_piva(cls, v):
        v = v.strip()
        if not _PIVA_RE.match(v): raise ValueError("Partita IVA non valida (11 cifre)")
        s = 0
        for i, ch in enumerate(v[:10]):
            n = ord(ch) - 48
            if i % 2 == 0: s += n
            else:
                n2 = 2 * n
                if n2 > 9: n2 -= 9
                s += n2
        if (10 - (s % 10)) % 10 != (ord(v[10]) - 48):
            raise ValueError("Partita IVA non valida (checksum)")
        return v

class AdminDecision(BaseModel):
    azione: Literal["approve", "reject"]
    motivo_rifiuto: Optional[str] = None
    @validator("motivo_rifiuto")
    def _motivo_se_reject(cls, v, values):
        if values.get("azione") == "reject" and not v:
            raise ValueError("Per rifiutare devi indicare un motivo_rifiuto.")
        return v

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _rest_select(params: Dict[str, Any]) -> Any:
    r = requests.get(f"{SUPABASE_URL}/rest/v1/{TABLE}", headers=_admin_headers(), params=params, timeout=20)
    if r.status_code != 200: raise HTTPException(status_code=500, detail=r.text)
    return r.json()

def _rest_insert(json: Dict[str, Any]) -> Any:
    r = requests.post(f"{SUPABASE_URL}/rest/v1/{TABLE}",
                      headers=_admin_headers({"Prefer": "return=representation"}), json=json, timeout=20)
    if r.status_code not in (200, 201): raise HTTPException(status_code=500, detail=r.text)
    data = r.json()
    return data[0] if isinstance(data, list) and data else data

def _rest_update(eq_id: str, json: Dict[str, Any]) -> Any:
    r = requests.patch(f"{SUPABASE_URL}/rest/v1/{TABLE}",
                       headers=_admin_headers({"Prefer": "return=representation"}),
                       params={"id": f"eq.{eq_id}"}, json=json, timeout=20)
    if r.status_code != 200: raise HTTPException(status_code=500, detail=r.text)
    data = r.json()
    return data[0] if isinstance(data, list) and data else data

def _rest_delete(eq_id: str) -> None:
    r = requests.delete(f"{SUPABASE_URL}/rest/v1/{TABLE}", headers=_admin_headers(),
                        params={"id": f"eq.{eq_id}"}, timeout=20)
    if r.status_code not in (200, 204): raise HTTPException(status_code=500, detail=r.text)

@router.get("", response_model=UtentiOut, dependencies=[Depends(require_bearer)])
def list_utenti():
    return _rest_select({
        "select": ",".join([
            "id","nome","username","email","is_active","role","tipo",
            "codice_fiscale","partita_iva","ragione_sociale",
            "stato","motivo_rifiuto","approved_by","approved_at",
            "created_at","updated_at"
        ]),
        "order": "created_at.desc",
    })

@router.get("/me", response_model=UtenteOut, dependencies=[Depends(_require_approved_user)])
def me(auth_user: Dict[str, Any] = Depends(get_auth_user)):
    uid = auth_user.get("id")
    data = _rest_select({"select": "*", "id": f"eq.{uid}", "limit": 1})
    if not data: raise HTTPException(status_code=404, detail="Profilo non trovato")
    return data[0]

@router.get("/{user_id}", response_model=UtenteOut, dependencies=[Depends(require_bearer)])
def get_utente(user_id: str):
    data = _rest_select({"select": "*", "id": f"eq.{user_id}", "limit": 1})
    if not data: raise HTTPException(status_code=404, detail="Utente non trovato")
    return data[0]

@router.post("/register/privato", response_model=UtenteOut, status_code=status.HTTP_201_CREATED)
def register_privato(body: RegistrazionePrivato, auth_user: Dict[str, Any] = Depends(get_auth_user)):
    uid = auth_user["id"]
    if _rest_select({"select": "id", "id": f"eq.{uid}", "limit": 1}):
        raise HTTPException(status_code=409, detail="Profilo già presente")
    rec = _rest_insert({
        "id": uid,
        "email": str(body.email),
        "nome": body.nome,
        "username": body.username,
        "tipo": "privato",
        "codice_fiscale": body.codice_fiscale.strip().upper(),
        "stato": "pending",
        "is_active": True,
        "role": "user",
    })
    try: notify_admin_new_signup(rec)
    except Exception: pass
    return rec

@router.post("/register/azienda", response_model=UtenteOut, status_code=status.HTTP_201_CREATED)
def register_azienda(body: RegistrazioneAzienda, auth_user: Dict[str, Any] = Depends(get_auth_user)):
    uid = auth_user["id"]
    if _rest_select({"select": "id", "id": f"eq.{uid}", "limit": 1}):
        raise HTTPException(status_code=409, detail="Profilo già presente")
    rec = _rest_insert({
        "id": uid,
        "email": str(body.email),
        "nome": body.nome,
        "username": body.username,
        "tipo": "azienda",
        "partita_iva": body.partita_iva,
        "ragione_sociale": body.ragione_sociale.strip(),
        "stato": "pending",
        "is_active": True,
        "role": "user",
    })
    try: notify_admin_new_signup(rec)
    except Exception: pass
    return rec

@router.get("/admin/pending", response_model=UtentiOut, dependencies=[Depends(_require_admin)])
def list_pending():
    return _rest_select({"select": "*", "stato": "eq.pending", "order": "created_at.asc"})

@router.patch("/admin/{user_id}", response_model=UtenteOut, dependencies=[Depends(_require_admin)])
def decide_user(user_id: str, decision: AdminDecision, auth_user: Dict[str, Any] = Depends(get_auth_user)):
    if decision.azione == "approve":
        patch = {"stato": "approved", "motivo_rifiuto": None, "approved_at": _now_iso(),
                 "approved_by": auth_user["id"], "is_active": True}
        esito = "approved"
    else:
        patch = {"stato": "rejected", "motivo_rifiuto": decision.motivo_rifiuto or "",
                 "approved_at": _now_iso(), "approved_by": auth_user["id"], "is_active": False}
        esito = "rejected"

    updated = _rest_update(user_id, patch)
    try:
        notify_user_decision(updated.get("email") or "", esito, updated.get("motivo_rifiuto"))
    except Exception:
        pass
    return updated
