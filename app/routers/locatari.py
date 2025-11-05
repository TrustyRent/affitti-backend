# app/routers/locatari.py
from fastapi import APIRouter, Depends, HTTPException, Query, status, Header
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Any, Dict

from app.core.security import get_current_user
from app.core.config import (
    get_supabase_read_client_for_token,
    get_supabase_write_client,
)

router = APIRouter(prefix="/locatari", tags=["locatari"])

class LocatarioIn(BaseModel):
    nome: str = Field(..., min_length=1, max_length=120)
    cognome: Optional[str] = Field(None, max_length=120)
    email: Optional[EmailStr] = None
    telefono: Optional[str] = Field(None, max_length=40)
    note: Optional[str] = Field(None, max_length=2000)

class LocatarioOut(LocatarioIn):
    id: str
    user_id: str

def _uid(current: Dict[str, Any]) -> Optional[str]:
    return (current or {}).get("id")

def _bearer_token(authorization: str) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None

# ----------------- CREATE -----------------
@router.post("", response_model=LocatarioOut, status_code=status.HTTP_201_CREATED, summary="Crea locatario")
def create_locatario(
    body: LocatarioIn,
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    supabase = get_supabase_write_client()
    data = body.model_dump()
    data["user_id"] = uid
    res = supabase.from_("locatari").insert(data).select("*").single().execute()
    if not res.data:
        raise HTTPException(status_code=400, detail="Creazione locatario fallita")
    return res.data

# ----------------- LIST -----------------
@router.get("", response_model=List[LocatarioOut], summary="Lista locatari")
def list_locatari(
    q: Optional[str] = Query(None, description="Ricerca su nome/cognome/email/telefono"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    authorization: str = Header(default=""),
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token mancante")

    supabase = get_supabase_read_client_for_token(token)
    query = supabase.from_("locatari").select("*").eq("user_id", uid).range(offset, offset + limit - 1)

    if q:
        query = query.or_(
            f"nome.ilike.%{q}%,cognome.ilike.%{q}%,email.ilike.%{q}%,telefono.ilike.%{q}%"
        )

    res = query.order("created_at", desc=True).execute()
    return res.data or []

# ----------------- READ -----------------
@router.get("/{loc_id}", response_model=LocatarioOut, summary="Dettaglio locatario")
def get_locatario(
    loc_id: str,
    authorization: str = Header(default=""),
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token mancante")

    supabase = get_supabase_read_client_for_token(token)
    res = (
        supabase.from_("locatari")
        .select("*")
        .eq("user_id", uid)
        .eq("id", loc_id)
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Locatario non trovato")
    return res.data

# ----------------- UPDATE -----------------
@router.put("/{loc_id}", response_model=LocatarioOut, summary="Aggiorna locatario")
def update_locatario(
    loc_id: str,
    body: LocatarioIn,
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    supabase = get_supabase_write_client()
    res = (
        supabase.from_("locatari")
        .update(body.model_dump())
        .eq("user_id", uid)
        .eq("id", loc_id)
        .select("*")
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Locatario non trovato")
    return res.data

# ----------------- DELETE -----------------
@router.delete("/{loc_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Elimina locatario")
def delete_locatario(
    loc_id: str,
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    supabase = get_supabase_write_client()
    _ = (
        supabase.from_("locatari")
        .delete()
        .eq("user_id", uid)
        .eq("id", loc_id)
        .execute()
    )
    return

# ----------------- RECENSIONI -----------------
class RecensioneIn(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    commento: Optional[str] = Field(None, max_length=2000)

class RecensioneOut(RecensioneIn):
    id: str
    user_id: str
    locatario_id: str
    created_at: Optional[str] = None

@router.get("/{loc_id}/recensioni", response_model=List[RecensioneOut], summary="Lista recensioni del locatario")
def list_recensioni_locatario(
    loc_id: str,
    authorization: str = Header(default=""),
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token mancante")

    supabase = get_supabase_read_client_for_token(token)
    res = (
        supabase.from_("recensioni_locatari")
        .select("*")
        .eq("user_id", uid)
        .eq("locatario_id", loc_id)
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []

@router.post("/{loc_id}/recensioni", response_model=RecensioneOut, status_code=status.HTTP_201_CREATED, summary="Aggiungi recensione")
def create_recensione_locatario(
    loc_id: str,
    body: RecensioneIn,
    current = Depends(get_current_user),
):
    uid = _uid(current)
    if not uid:
        raise HTTPException(status_code=401, detail="Utente non valido")

    supabase = get_supabase_write_client()
    payload = {
        "user_id": uid,
        "locatario_id": loc_id,
        "rating": body.rating,
        "commento": body.commento,
    }
    res = (
        supabase.from_("recensioni_locatari")
        .insert(payload)
        .select("*")
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=400, detail="Creazione recensione fallita")
    return res.data
