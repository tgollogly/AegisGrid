"""Fake internet-exposed freezer controller (toy HTTP, not a real field protocol)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# Weak factory default, in the spirit of the 2026 supermarket attacks.
DEFAULT_PASSWORD = "admin"
UPSTREAM_GUARD_SECRET = "guard-internal-only"


class FridgeController:
    def __init__(self, fridge, host="127.0.0.1", port=0, require_guard=False):
        self.fridge = fridge
        self.host = host
        self.port = port
        self.require_guard = require_guard
        self._httpd = None
        self._thread = None
        self.command_log = []

    def start(self):
        controller = self

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
                if urlparse(self.path).path != "/status":
                    self._send(404, {"error": "not found"})
                    return
                blocked = controller._check_access(self)
                if blocked:
                    self._send(*blocked)
                    return
                self._send(200, controller.fridge.status())

            def do_POST(self):
                if urlparse(self.path).path != "/command":
                    self._send(404, {"error": "not found"})
                    return
                blocked = controller._check_access(self)
                if blocked:
                    self._send(*blocked)
                    return
                data = self._read_json()
                if data is None:
                    self._send(400, {"error": "invalid json"})
                    return
                code, payload = controller.handle_command(data)
                self._send(code, payload)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def _check_access(self, handler):
        if self.require_guard:
            secret = handler.headers.get("X-Upstream-Guard", "")
            if secret != UPSTREAM_GUARD_SECRET:
                self.command_log.append({"blocked": "direct_access"})
                return 403, {"error": "forbidden", "reason": "controller is not exposed to the internet"}
        return None

    def handle_command(self, data):
        password = str(data.get("password", ""))
        action = str(data.get("action", data.get("command", "")))
        if password != DEFAULT_PASSWORD:
            self.command_log.append({"blocked": "bad_password", "action": action})
            return 401, {"error": "unauthorized", "reason": "bad password"}

        if action == "status":
            return 200, {"ok": True, **self.fridge.status()}

        if action == "set_temp":
            if "temp" not in data and "temp_c" not in data:
                return 400, {"error": "missing temp"}
            temp = float(data.get("temp", data.get("temp_c")))
            self.fridge.set_temp(temp)
            self.command_log.append({"action": "set_temp", "temp": temp})
            return 200, {"ok": True, **self.fridge.status()}

        if action == "defrost_on":
            duration = int(data.get("duration", data.get("duration_min", 30)))
            self.fridge.defrost_on(duration)
            self.command_log.append({"action": "defrost_on", "duration": duration})
            return 200, {"ok": True, **self.fridge.status()}

        return 400, {"error": "unknown action", "action": action}

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
