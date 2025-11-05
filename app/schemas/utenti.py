from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Literal
from datetime import datetime
import re

# --- Regex e validatori base Italia ---
_CF_RE = re.compile(r"^[A-Z0-9]{16}$", re.IGNORECASE)
_PIVA_RE = re.compile(r"^[0-9]{11}$")

def _valida_cf(cf: str) -> str:
    cf = cf.strip().upper()
    if not _CF_RE.match(cf):
        raise ValueError("Codice fiscale non valido (16 caratteri alfanumerici).")
    # (Se vuoi aggiungiamo in seguito il controllo di checksum CF)
    return cf

def _valida_piva(piva: str) -> str:
    piva = piva.strip()
    if not _PIVA_RE.match(piva):
        raise ValueError("Partita IVA non valida (11 cifre).")
    # Checksum ufficiale P.IVA
    s = 0
    for i, ch in enumerate(piva[:10]):
        n = ord(ch) - ord('0')
        if (i % 2) == 0:  # posizioni 1,3,5,... (base 1)
            s += n
        else:
            n2 = 2 * n
            if n2 > 9:
                n2 -= 9
            s += n2
    controllo = (10 - (s % 10)) % 10
    if controllo != (ord(piva[10]) - ord('0')):
        raise ValueError("Partita IVA non valida (checksum).")
    return piva

TipoUtente = Literal["privato", "azienda"]
StatoUtente = Literal["pending", "approved", "rejected"]

class BaseUtente(BaseModel):
    email: EmailStr
    nome: Optional[str] = None
    cognome: Optional[str] = None
    tipo: TipoUtente = "privato"

class RegistrazionePrivato(BaseUtente):
    tipo: TipoUtente = "privato"
    codice_fiscale: str = Field(..., description="Codice fiscale per privati")

    @validator("codice_fiscale")
    def _check_cf(cls, v):
        return _valida_cf(v)

class RegistrazioneAzienda(BaseUtente):
    tipo: TipoUtente = "azienda"
    partita_iva: str = Field(..., description="Partita IVA per aziende")
    ragione_sociale: str = Field(..., min_length=2)

    @validator("partita_iva")
    def _check_piva(cls, v):
        return _valida_piva(v)

class UtenteOut(BaseModel):
    id: str
    email: EmailStr
    username: Optional[str] = None
    nome: Optional[str] = None
    cognome: Optional[str] = None
    tipo: TipoUtente
    codice_fiscale: Optional[str] = None
    partita_iva: Optional[str] = None
    ragione_sociale: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    stato: StatoUtente
    motivo_rifiuto: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class AdminDecision(BaseModel):
    azione: Literal["approve", "reject"]
    motivo_rifiuto: Optional[str] = None

    @validator("motivo_rifiuto")
    def _motivo_se_reject(cls, v, values):
        if values.get("azione") == "reject" and not v:
            raise ValueError("Per rifiutare devi indicare un motivo_rifiuto.")
        return v
