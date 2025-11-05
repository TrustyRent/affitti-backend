# app/core/emailer.py
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, Optional, List

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip() or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "noreply@example.com").strip()
ADMIN_EMAILS: List[str] = [e.strip() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]

def _as_list(value) -> List[str]:
    """Garantisce sempre una lista di stringhe (accetta str/list/tuple/set/None)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        v = value.strip()
        return [v] if v else []
    return [str(value).strip()]

def _send_email(to: Iterable[str] | str, subject: str, text: str, html: Optional[str] = None) -> bool:
    """
    Invia una mail. `to` può essere stringa o lista.
    Firma più naturale: (to, subject, text, html=None)
    """
    to_list = _as_list(to)
    if not (SMTP_HOST and SMTP_PORT and SMTP_FROM and to_list):
        print("⚠️  _send_email: SMTP non configurato o destinatari vuoti. Salto invio.")
        return False

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_list)
    msg["Subject"] = subject
    msg.set_content(text or "")
    if html:
        msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    try:
        print(f"📤 Invio email a: {msg['To']} | Soggetto: {subject}")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"✅ Email inviata a {msg['To']}")
        return True
    except Exception as e:
        print(f"❌ Errore invio email a {msg['To']}: {e}")
        return False

def notify_admin_new_signup(profilo: dict) -> None:
    """
    profilo: record 'utenti' appena creato (id, email, tipo, username, ecc.)
    """
    if not ADMIN_EMAILS:
        print("ℹ️  notify_admin_new_signup: ADMIN_EMAILS vuoto. Salto invio.")
        return

    user_id = profilo.get("id", "")
    email = profilo.get("email", "")
    tipo = profilo.get("tipo", "")
    username = profilo.get("username") or ""
    cf = profilo.get("codice_fiscale") or "-"
    piva = profilo.get("partita_iva") or "-"
    ragsoc = profilo.get("ragione_sociale") or "-"

    subject = "Nuova richiesta di registrazione"
    text = f"Nuova richiesta da {email} ({tipo})."
    html = f"""
    <h2>Nuova richiesta di registrazione</h2>
    <p><b>User ID:</b> {user_id}</p>
    <p><b>Email:</b> {email}</p>
    <p><b>Tipo:</b> {tipo}</p>
    <p><b>Username:</b> {username}</p>
    <p><b>Codice Fiscale:</b> {cf}</p>
    <p><b>Partita IVA:</b> {piva}</p>
    <p><b>Ragione Sociale:</b> {ragsoc}</p>
    <hr/>
    <p>Apri l'area amministratore per <b>approvare</b> o <b>rifiutare</b> l'utente.</p>
    """
    _send_email(ADMIN_EMAILS, subject, text, html)

def notify_user_decision(email: str, esito: str, motivo: Optional[str] = None) -> None:
    """
    esito: 'approved' | 'rejected'
    """
    if not email:
        print("ℹ️  notify_user_decision: email destinatario vuota. Salto invio.")
        return

    if esito == "approved":
        subject = "Il tuo account è stato approvato"
        text = "La tua registrazione è stata approvata. Ora puoi accedere al portale."
        html = "<h2>Benvenuto!</h2><p>La tua richiesta è stata <b>approvata</b>. Ora puoi accedere al portale.</p>"
    else:
        subject = "La tua registrazione è stata rifiutata"
        motivo_txt = motivo or "Nessun motivo specificato."
        text = f"Registrazione rifiutata. Motivo: {motivo_txt}"
        html = f"<h2>Registrazione rifiutata</h2><p>Motivo: <b>{motivo_txt}</b></p>"

    _send_email(email, subject, text, html)  # può essere str o list
