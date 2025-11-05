# app/core/database.py
from __future__ import annotations

import os
from typing import Optional, Any, Dict, AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from postgrest import AsyncPostgrestClient, APIError

# --- Caricamento .env (prima di leggere le env) ---
env_paths = [
    Path(".") / ".env",                                   # se lanci dalla root
    Path(__file__).resolve().parents[2] / ".env",         # <repo>/.env (fallback)
]
for p in env_paths:
    if p.exists():
        load_dotenv(dotenv_path=p)
        break
else:
    load_dotenv()  # ultimo tentativo: cwd

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing env var: {name}")
    return val

SUPABASE_URL = _require_env("SUPABASE_URL").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = _require_env("SUPABASE_SERVICE_ROLE_KEY")

# Endpoint REST di Supabase/PostgREST
POSTGREST_URL = f"{SUPABASE_URL}/rest/v1"

DEFAULT_HEADERS = {
    "apikey": SUPABASE_SERVICE_ROLE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
}

class Repository:
    """
    Metodi usati da auth/security/utenti:
      - users_find_one(username_or_email)
      - users_get_by_id(user_id)
      - users_increment_token_version(user_id)
    """

    def __init__(self, client: AsyncPostgrestClient):
        self.client = client

    async def users_find_one(self, username_or_email: str) -> Optional[Dict[str, Any]]:
        v = (username_or_email or "").strip()
        if not v:
            return None
        try:
            r_email = await (
                self.client
                .from_("utenti")
                .select("id,username,email,password_hash,is_active,role,token_version")
                .filter("email", "ilike", v)
                .limit(1)
                .execute()
            )
            rows = r_email.data or []
            if rows:
                return rows[0]
        except APIError:
            pass
        try:
            r_user = await (
                self.client
                .from_("utenti")
                .select("id,username,email,password_hash,is_active,role,token_version")
                .filter("username", "ilike", v)
                .limit(1)
                .execute()
            )
            rows = r_user.data or []
            if rows:
                return rows[0]
        except APIError:
            return None
        return None

    async def users_get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await (
                self.client
                .from_("utenti")
                .select("id,username,email,password_hash,is_active,role,token_version")
                .eq("id", user_id)
                .limit(1)
                .execute()
            )
        except APIError:
            return None
        data = resp.data or []
        return data[0] if data else None

    async def users_increment_token_version(self, user_id: str) -> int:
        try:
            resp = await self.client.rpc("inc_token_version", {"uid": user_id}).execute()
        except APIError as e:
            raise RuntimeError(f"inc_token_version RPC failed: {e}") from e

        val = resp.data
        if isinstance(val, list) and val:
            first = val[0]
            if isinstance(first, dict):
                return int(list(first.values())[0])
            return int(first)
        return int(val)

# ---- client context ----
@asynccontextmanager
async def _client_ctx():
    client = AsyncPostgrestClient(
        POSTGREST_URL,
        headers=DEFAULT_HEADERS,
        schema="public",
    )
    try:
        yield client
    finally:
        await client.aclose()

async def get_db() -> AsyncGenerator[Repository, None]:
    """Dependency FastAPI: yield un Repository pronto."""
    async with _client_ctx() as c:
        yield Repository(c)

# === COMPATIBILITÀ CON LE VECCHIE ROTTE LOCATARI ===
# Le rotte locatari.py usano ancora queste funzioni sincrone
# per compatibilità con le vecchie versioni del client Supabase.
from supabase import create_client, Client

def get_supabase_read_client() -> Client:
    """Client Supabase per lettura"""
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def get_supabase_write_client() -> Client:
    """Client Supabase per scrittura"""
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
