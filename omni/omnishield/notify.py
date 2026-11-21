"""Send a daily invitation to pray, only to people who asked for it.

Consent is checked per recipient, one message per person per day is enforced,
and the default mode is a dry run that writes the log without touching the
network. A webhook or SMTP channel is used only when explicitly configured.
"""

from __future__ import annotations

import json
import os
import smtplib
import time
import urllib.request
from collections.abc import Mapping
from email.message import EmailMessage
from pathlib import Path
from typing import Any


class NotifyError(Exception):
    pass


def load_recipients(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.is_file():
        raise NotifyError(f"no recipient file at {target}")
    document = json.loads(target.read_text(encoding="utf-8"))
    rows = document.get("recipients") if isinstance(document, dict) else document
    if not isinstance(rows, list) or not rows:
        raise NotifyError("the recipient file has no recipients")
    recipients = []
    for row in rows:
        if not isinstance(row, dict):
            raise NotifyError("every recipient must be an object")
        if not row.get("consent"):
            continue
        if not (row.get("email") or row.get("webhook")):
            raise NotifyError("a recipient needs an email or a webhook")
        recipients.append(
            {
                "name": str(row.get("name", "")),
                "email": row.get("email"),
                "webhook": row.get("webhook"),
                "consent": True,
            }
        )
    if not recipients:
        raise NotifyError("no recipient has given consent")
    return recipients


def message_for(entry: Mapping[str, Any]) -> dict[str, str]:
    theme = entry.get("theme", "shukrani")
    lines = entry.get("psalm") or []
    body = "\n".join(
        [
            f"Habari za asubuhi. Leo ni siku ya {theme}.",
            "",
            *[f"  {line}" for line in lines],
            "",
            f"Wimbo: {entry.get('song', {}).get('title', '')}",
            "",
            "Umealikwa kwa hiari yako. Kama hutaki barua hizi, jibu neno ONDOA.",
            "Ombi hili linatumwa na mfumo unaojulisha kwa niaba ya mtu aliyekuandikisha.",
        ]
    )
    return {"subject": f"Kumbusho la leo: {theme}", "body": body}


class Notifier:
    def __init__(
        self,
        state_path: str | os.PathLike[str],
        *,
        dry_run: bool = True,
        limit_per_day: int = 1,
        webhook_timeout: float = 10.0,
        smtp: Mapping[str, Any] | None = None,
    ) -> None:
        if limit_per_day < 1:
            raise NotifyError("the daily limit must be positive")
        self.state_path = Path(state_path)
        self.dry_run = dry_run
        self.limit_per_day = limit_per_day
        self.webhook_timeout = webhook_timeout
        self.smtp = dict(smtp) if smtp else None
        self.sent: dict[str, list[str]] = {}
        if self.state_path.is_file():
            self.sent = json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.sent, sort_keys=True), encoding="utf-8")
        os.chmod(self.state_path, 0o600)

    def _deliver(self, recipient: Mapping[str, Any], message: Mapping[str, str]) -> dict[str, Any]:
        if self.dry_run:
            return {"channel": "dry-run", "delivered": False}
        if recipient.get("webhook"):
            request = urllib.request.Request(
                str(recipient["webhook"]),
                data=json.dumps({"subject": message["subject"], "body": message["body"]}).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "OmniShield/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.webhook_timeout) as response:
                return {"channel": "webhook", "delivered": 200 <= response.status < 300, "status": response.status}
        if recipient.get("email"):
            if not self.smtp:
                raise NotifyError("an email recipient needs an SMTP configuration")
            mail = EmailMessage()
            mail["Subject"] = message["subject"]
            mail["From"] = self.smtp.get("sender", "")
            mail["To"] = str(recipient["email"])
            mail.set_content(message["body"])
            with smtplib.SMTP(self.smtp["host"], int(self.smtp.get("port", 587)), timeout=15) as client:
                if self.smtp.get("starttls", True):
                    client.starttls()
                if self.smtp.get("user"):
                    client.login(self.smtp["user"], self.smtp.get("password", ""))
                client.send_message(mail)
            return {"channel": "email", "delivered": True}
        raise NotifyError("the recipient has no usable channel")

    def send(self, recipients: list[dict[str, Any]], message: Mapping[str, str], *, day: str | None = None) -> dict[str, Any]:
        if not recipients:
            raise NotifyError("no recipients to notify")
        today = day or time.strftime("%Y-%m-%d")
        delivered = []
        skipped = []
        for recipient in recipients:
            key = str(recipient.get("email") or recipient.get("webhook"))
            already = self.sent.setdefault(key, [])
            if len(already) >= self.limit_per_day and today in already:
                skipped.append({"to": key, "reason": "already sent today"})
                continue
            if not recipient.get("consent"):
                skipped.append({"to": key, "reason": "no consent"})
                continue
            result = self._deliver(recipient, message)
            already.append(today)
            delivered.append({"to": key, **result})
        self._save()
        return {
            "day": today,
            "dry_run": self.dry_run,
            "delivered": delivered,
            "skipped": skipped,
            "recipients": len(recipients),
        }
