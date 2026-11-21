import http.server
import json
import threading

import pytest

from omnishield.notify import Notifier, NotifyError, load_recipients, message_for
from omnishield.worship import office


def _write(tmp_path, rows):
    path = tmp_path / "recipients.json"
    path.write_text(json.dumps({"recipients": rows}), encoding="utf-8")
    return path


def test_recipients_need_consent_and_a_channel(tmp_path):
    path = _write(
        tmp_path,
        [
            {"name": "A", "email": "a@example.test", "consent": True},
            {"name": "B", "email": "b@example.test", "consent": False},
        ],
    )
    recipients = load_recipients(path)
    assert [row["email"] for row in recipients] == ["a@example.test"]
    with pytest.raises(NotifyError):
        load_recipients(_write(tmp_path, [{"email": "x@example.test"}]))
    with pytest.raises(NotifyError):
        load_recipients(tmp_path / "missing.json")


def test_dry_run_is_the_default_and_is_limited_to_one_a_day(tmp_path):
    recipients = load_recipients(_write(tmp_path, [{"email": "a@example.test", "consent": True}]))
    notifier = Notifier(tmp_path / "state.json")
    message = message_for(office(day=0))
    first = notifier.send(recipients, message, day="2026-11-21")
    second = notifier.send(recipients, message, day="2026-11-21")
    assert first["dry_run"] is True
    assert first["delivered"][0]["channel"] == "dry-run"
    assert second["delivered"] == []
    assert second["skipped"][0]["reason"] == "already sent today"
    assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600


def test_message_contains_opt_in_and_unsubscribe(tmp_path):
    message = message_for(office(day=1))
    assert "ONDAA" not in message["body"]
    assert "OND" in message["body"]
    assert "hiari" in message["body"]
    assert message["subject"].startswith("Kumbusho la leo")


def test_webhook_delivery_posts_json(tmp_path):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/hook"
        recipients = load_recipients(_write(tmp_path, [{"webhook": url, "consent": True}]))
        notifier = Notifier(tmp_path / "state.json", dry_run=False)
        result = notifier.send(recipients, message_for(office(day=2)), day="2026-11-22")
        assert result["delivered"][0]["status"] == 204
        assert received and received[0]["subject"].startswith("Kumbusho")
    finally:
        server.shutdown()
        thread.join()
