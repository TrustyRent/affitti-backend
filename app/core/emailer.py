# app/core/emailer.py
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Optional, Dict, Any

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER or "no-reply@example.com")
# Dove vuoi ricevere le notifiche admin (può essere più di una, separate da virgola)
ADMIN_NOTIFY_EMAILS = [e.strip() for e in (os.getenv("ADMIN_NOTIFY_EMAILS", "")).split(",") if e.strip()]

def _can_send() -> bool:
    # abilita invio solo se host e user sono valorizzati
    return bool(SMTP_HOST and SMTP_USER and EMAIL_FROM)

def _send_mail(subject: str, to_list: list[str], text: str, html: Optional[str] = None) -> None:
    if not _can_send() or not to_list:
        # Nessuna eccezione: fallback silenzioso per ambienti dev
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(to_list)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# ============ Notifiche dominio ============
def notify_admin_new_signup(rec: Dict[str, Any]) -> None:
    """Avvisa gli admin quando un utente completa la registrazione profilo (stato 'pending')."""
    if not ADMIN_NOTIFY_EMAILS:
        return
    uid = rec.get("id", "")
    email = rec.get("email", "")
    tipo = rec.get("tipo", "privato")
    ragione = rec.get("ragione_sociale") or "-"
    subject = f"[TrustyRent] Nuova registrazione in approvazione ({tipo})"
    text = (
        "Ciao Admin,\n\n"
        "è stata inviata una nuova richiesta di approvazione profilo.\n\n"
        f"ID: {uid}\n"
        f"Email: {email}\n"
        f"Tipo: {tipo}\n"
        f"Ragione sociale: {ragione}\n"
        "\nAccedi alla dashboard admin per gestirla.\n"
    )
    html = f"""
    <p>Ciao Admin,</p>
    <p>È stata inviata una nuova richiesta di approvazione profilo.</p>
    <ul>
      <li><b>ID:</b> {uid}</li>
      <li><b>Email:</b> {email}</li>
      <li><b>Tipo:</b> {tipo}</li>
      <li><b>Ragione sociale:</b> {ragione}</li>
    </ul>
    <p>Accedi alla dashboard admin per gestirla.</p>
    """
    _send_mail(subject, ADMIN_NOTIFY_EMAILS, text, html)

def notify_user_decision(user_email: str, esito: str, motivo: Optional[str]) -> None:
    """Comunica all’utente l’esito dell’approvazione (approved/rejected)."""
    if not user_email:
        return
    esito = (esito or "").lower()
    if esito == "approved":
        subject = "[TrustyRent] Account approvato 🎉"
        text = (
            "Ciao,\n\n"
            "la tua richiesta è stata approvata. Ora puoi utilizzare tutte le funzionalità della piattaforma.\n\n"
            "Buon lavoro!\n"
        )
        html = """
        <p>Ciao,</p>
        <p>La tua richiesta è stata <b>approvata</b>. Ora puoi utilizzare tutte le funzionalità della piattaforma.</p>
        <p>Buon lavoro!</p>
        """
    else:
        subject = "[TrustyRent] Account rifiutato"
        motivo_str = motivo or "Non specificato."
        text = (
            "Ciao,\n\n"
            "purtroppo la tua richiesta è stata rifiutata.\n"
            f"Motivo: {motivo_str}\n\n"
            "Se ritieni ci sia un errore, rispondi a questa email.\n"
        )
        html = f"""
        <p>Ciao,</p>
        <p>Purtroppo la tua richiesta è stata <b>rifiutata</b>.</p>
        <p><b>Motivo:</b> {motivo_str}</p>
        <p>Se ritieni ci sia un errore, rispondi a questa email.</p>
        """
    _send_mail(subject, [user_email], text, html)
