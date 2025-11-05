# app/core/config.py
from __future__ import annotations

import os
from functools import lru_cache

# Carica .env solo in sviluppo (evita in produzione)
if os.getenv("ENV", "development") != "production":
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv()
    except Exception:
        pass

try:
    from supabase import create_client, Client  # type: ignore
except Exception as e:
    raise RuntimeError(
        "Libreria 'supabase' non disponibile. Installa con: pip install supabase"
    ) from e


@lru_cache
def get_clients() -> tuple["Client", "Client | None"]:
    """
    Restituisce (read_client, write_client).
    - read_client usa ANON KEY → per chiamate senza privilegi
    - write_client (opzionale) usa SERVICE KEY → operazioni privilegiate lato DB
    """
    url = os.getenv("SUPABASE_URL")
    anon_key = os.getenv("SUPABASE_ANON_KEY")
    # supporta entrambi i nomi che usi nel progetto
    service_key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not anon_key:
        raise RuntimeError(
            "Supabase non configurato: servono SUPABASE_URL e SUPABASE_ANON_KEY "
            "(opzionale SUPABASE_SERVICE_KEY / SUPABASE_SERVICE_ROLE_KEY)."
        )

    read_client = create_client(url, anon_key)
    write_client = create_client(url, service_key) if service_key else None
    return read_client, write_client


def get_supabase_read_client():
    rc, _ = get_clients()
    return rc


def get_supabase_write_client():
    _, wc = get_clients()
    return wc


def get_supabase_read_client_for_token(token: str):
    """
    Client di lettura con header Authorization impostato al JWT dell'utente.
    Serve per far funzionare le SELECT sotto RLS (es. policy user_id = auth.uid()).
    """
    url = os.getenv("SUPABASE_URL")
    anon_key = os.getenv("SUPABASE_ANON_KEY")
    if not url or not anon_key:
        raise RuntimeError("Supabase non configurato (URL/ANON KEY mancanti).")

    client = create_client(url, anon_key)
    try:
        # supabase-py v2: imposta Authorization: Bearer <token> per PostgREST
        client.postgrest.auth(token)
    except Exception:
        # fallback silenzioso: se auth() non è disponibile, le query potrebbero risultare vuote con RLS
        pass
    return client
