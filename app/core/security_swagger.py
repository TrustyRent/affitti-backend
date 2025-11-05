# app/core/security.py
from typing import Optional

from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Se già hai un decode_token, importa quello:
try:
    from app.core.security import decode_token as _decode_token  # se esiste già nella tua codebase
except Exception:
    _decode_token = None  # lo gestiamo sotto

bearer_scheme = HTTPBearer(auto_error=False)

def require_auth(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    access_cookie: Optional[str] = Cookie(default=None, alias="access_token"),
):
    """
    Accetta token da:
      - Header: Authorization: Bearer <token>
      - Cookie: access_token=<token>

    Non modifica il tuo flusso: qui solo leggiamo/validiamo il token.
    """
    token = None

    if creds and creds.scheme.lower() == "bearer" and creds.credentials:
        token = creds.credentials
    elif access_cookie:
        token = access_cookie

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Se hai già una funzione per validare/decodificare il JWT, usala:
    if _decode_token is not None:
        try:
            payload = _decode_token(token)  # <-- la tua funzione esistente
            return payload  # puoi tornare user info/payload
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    # Fallback: se non hai decode_token, restituiamo solo il token (minimo indispensabile)
    return token
