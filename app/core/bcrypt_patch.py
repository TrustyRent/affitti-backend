# app/core/bcrypt_patch.py
import os
try:
    import passlib.hash as _ph
    _ph.bcrypt = _ph.bcrypt.using(truncate_error=True)  # solleva errore >72 byte
    if os.getenv("AFFITTI_BCRYPT_DEBUG", "0") == "1":
        print("[affitti] bcrypt_patch attiva: truncate_error=True")
except Exception:
    pass
