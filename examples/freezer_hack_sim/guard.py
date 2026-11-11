"""Local gateway proxy: staff token, freezer bounds, trip + simulated SMS log.

Mirrors AegisGrid ideas (operator token, hard temperature limits, fail-closed)
in a minimal HTTP toy—not the production DuckDB engine in ``core.py``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .controller import UPSTREAM_GUARD_SECRET
from .fridge import FREEZER_MAX_C, FREEZER_MIN_C

# Simulated allow-listed staff token (stand-in for VPN / staff channel).
STAFF_TOKEN = "staff-token-ok"
# A normal defrost cycle is short. A long forced defrost is the attack.
MAX_DEFROST_MIN = 15


class GuardBox:
    def __init__(self, fridge, controller_url, host="127.0.0.1", port=0):
        self.fridge = fridge
        self.controller_url = controller_url.rstrip("/")
        self.host = host
        self.port = port
        self.tripped = False
        self.sms_alerts = []
        self.event_log = []
        self._httpd = None
        self._thread = None

    def start(self):
        guard = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _read_json(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    return json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    return None

            def _send(self, code, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlparse(self.path).path
                if path == "/guard/status":
                    self._send(200, guard.guard_status())
                    return
                if path != "/status":
                    self._send(404, {"error": "not found"})
                    return
                auth = guard._check_token(self)
                if auth:
                    self._send(*auth)
                    return
                code, payload = guard.forward("GET", "/status", None)
                self._send(code, payload)

            def do_POST(self):
                if urlparse(self.path).path != "/command":
                    self._send(404, {"error": "not found"})
                    return
                auth = guard._check_token(self)
                if auth:
                    self._send(*auth)
                    return
                data = self._read_json()
                if data is None:
                    self._send(400, {"error": "invalid json"})
                    return
                code, payload = guard.handle_staff_command(data)
                self._send(code, payload)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def _check_token(self, handler):
        token = handler.headers.get("X-Staff-Token", "")
        if token != STAFF_TOKEN:
            self.event_log.append({"blocked": "unknown_source_or_bad_token"})
            return 401, {
                "error": "unauthorized",
                "reason": "only allow-listed staff token (simulated VPN) is accepted",
            }
        return None

    def handle_staff_command(self, data):
        action = str(data.get("action", data.get("command", "")))

        if action == "status":
            return self.forward("POST", "/command", {"password": data.get("password", ""), "action": "status"})

        if action == "set_temp":
            if "temp" not in data and "temp_c" not in data:
                return 400, {"error": "missing temp"}
            temp = float(data.get("temp", data.get("temp_c")))
            if temp < FREEZER_MIN_C or temp > FREEZER_MAX_C:
                self._trip(f"rejected unsafe set_temp {temp}C (allowed {FREEZER_MIN_C}C to {FREEZER_MAX_C}C)")
                return 403, {
                    "error": "rejected",
                    "reason": "temperature outside freezer bounds",
                    "tripped": True,
                    "allowed_min_c": FREEZER_MIN_C,
                    "allowed_max_c": FREEZER_MAX_C,
                }
            return self.forward("POST", "/command", {"password": "admin", "action": "set_temp", "temp": temp})

        if action == "defrost_on":
            duration = int(data.get("duration", data.get("duration_min", 30)))
            if duration > MAX_DEFROST_MIN:
                self._trip(f"rejected forced defrost of {duration} min (limit {MAX_DEFROST_MIN} min)")
                return 403, {
                    "error": "rejected",
                    "reason": "defrost duration above limit",
                    "tripped": True,
                    "max_defrost_min": MAX_DEFROST_MIN,
                }
            return self.forward("POST", "/command", {"password": "admin", "action": "defrost_on", "duration": duration})

        return 400, {"error": "unknown action", "action": action}

    def _trip(self, reason):
        self.tripped = True
        self.fridge.cancel_defrost_keep_cooling()
        sms = f"SMS ALERT: Fridge circuit tripped. {reason}. Freezer still cooling."
        self.sms_alerts.append(sms)
        self.event_log.append({"trip": True, "reason": reason, "sms": sms})
        print(sms, flush=True)

    def forward(self, method, path, data):
        from .client import http_json

        return http_json(
            method,
            self.controller_url + path,
            data=data,
            headers={"X-Upstream-Guard": UPSTREAM_GUARD_SECRET},
        )

    def guard_status(self):
        return {
            "tripped": self.tripped,
            "sms_alerts": list(self.sms_alerts),
            "events": list(self.event_log),
            "fridge": self.fridge.status(),
        }

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
