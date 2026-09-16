"""Alerting & notification delivery (PS26156-f derived hooks).

Notifiers are small transport adapters with one method
``notify(severity, title, body)``. The orchestrator broadcasts critical /
high alerts; every transport is optional and failure-tolerant so the demo
never depends on external services.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List

log = logging.getLogger("trinetra.notifier")

MANDATORY_SEVERITIES = ("critical", "high")


class ConsoleNotifier:
    """Human-readable log sink — always present."""

    name = "console"

    def notify(self, severity: str, title: str, body: str) -> Dict[str, Any]:
        if severity in MANDATORY_SEVERITIES:
            log.warning("ALERT [%s] %s\n%s", severity.upper(), title, body)
        else:
            log.info("NOTICE [%s] %s", severity.upper(), title)
        return {"transport": self.name, "status": "sent", "severity": severity}


class EmailNotifier:
    """SMTP alerting (optional; env-configured)."""

    name = "email"

    def __init__(self, host: str = "", port: int = 587, sender: str = "",
                 recipient: str = "", username: str = "", password: str = "") -> None:
        self.host = host or os.environ.get("TRINETRA_SMTP_HOST", "")
        self.port = int(port or os.environ.get("TRINETRA_SMTP_PORT", "587"))
        self.sender = sender or os.environ.get("TRINETRA_SMTP_FROM", "")
        self.recipient = recipient or os.environ.get("TRINETRA_SMTP_TO", "")
        self.username = username or os.environ.get("TRINETRA_SMTP_USER", "")
        self.password = password or os.environ.get("TRINETRA_SMTP_PASS", "")

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender and self.recipient)

    def notify(self, severity: str, title: str, body: str) -> Dict[str, Any]:
        if not self.configured or severity not in MANDATORY_SEVERITIES:
            return {"transport": self.name, "status": "skipped", "reason": "unconfigured / low severity"}
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"[TriNetra] {severity.upper()}: {title}"
        msg["From"] = self.sender
        msg["To"] = self.recipient
        try:
            if self.port == 465:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=15) as smtp:
                    if self.username:
                        smtp.login(self.username, self.password)
                    smtp.sendmail(self.sender, [self.recipient], msg.as_string())
            else:
                with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
                    if self.port == 587:
                        smtp.starttls()
                    if self.username:
                        smtp.login(self.username, self.password)
                    smtp.sendmail(self.sender, [self.recipient], msg.as_string())
            return {"transport": self.name, "status": "sent", "severity": severity}
        except Exception as exc:  # noqa: BLE001
            log.warning("email notify failed: %s", exc)
            return {"transport": self.name, "status": "error", "error": str(exc)}


class Notifier:
    """Fan-out hub — calls every registered notifier, always returns."""

    def __init__(self, notifiers: List[Any] | None = None) -> None:
        self.notifiers = notifiers or [ConsoleNotifier(), EmailNotifier()]

    def notify(self, severity: str, title: str, body: str) -> List[Dict[str, Any]]:
        results = []
        for transport in self.notifiers:
            try:
                results.append(transport.notify(severity, title, body))
            except Exception as exc:  # noqa: BLE001
                results.append({"transport": getattr(transport, "name", "?"),
                                "status": "error", "error": str(exc)})
        return results

    def alert(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Dispatch one Module A/B finding dict (PS26145 alert schema)."""
        alert = finding.get("alert", finding)
        severity = str(alert.get("severity", "high"))
        title = alert.get("threat_class", "unknown threat")
        flow_id = alert.get("flow_id", "?")
        body_lines = [
            f"threat_class : {title}",
            f"flow_id      : {flow_id}",
            f"confidence   : {alert.get('confidence', '?')}",
        ]
        if alert.get("evidence"):
            body_lines.append("evidence     : " + str(alert["evidence"])[:400])
        return self.notify(severity, title, "\n".join(body_lines))