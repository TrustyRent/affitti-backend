import os
print("[sitecustomize] loaded")

from passlib.handlers import bcrypt as _bcrypt_mod
from passlib import hash as _hash_pkg
from passlib.hash import bcrypt_sha256 as _bcrypt_sha256

# 1) Disattiva l’errore >72 byte OVUNQUE
try:
    _bcrypt_mod.bcrypt = _bcrypt_mod.bcrypt.using(truncate_error=False)
    _hash_pkg.bcrypt   = _bcrypt_mod.bcrypt
except Exception as _e:
    print("[sitecustomize] bcrypt using() patch failed:", _e)

# 2) Verifica “safe” con fallback a 72 byte
_orig_verify = _bcrypt_mod.bcrypt.verify
def _safe_verify(secret, hashed, **kw):
    try:
        return _orig_verify(secret, hashed, **kw)
    except ValueError as e:
        if "password cannot be longer than 72 bytes" in str(e):
            try:
                return _orig_verify(secret[:72], hashed, **kw)
            except Exception:
                return False
        raise
_bcrypt_mod.bcrypt.verify = _safe_verify

# 3) (opzionale) forza hashing in sha256 per chi usa ancora bcrypt.hash
if os.getenv("BCRYPT_FORCE_SHA256", "0") == "1":
    _bcrypt_mod.bcrypt.hash = _bcrypt_sha256.hash
