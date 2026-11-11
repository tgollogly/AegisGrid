"""Tiny localhost-only JSON HTTP helper."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def http_json(method, url, data=None, headers=None, timeout=2.0):
    if not url.startswith("http://127.0.0.1:") and not url.startswith("http://localhost:"):
        raise ValueError(f"refusing non-localhost URL: {url}")
    body = None if data is None else json.dumps(data).encode("utf-8")
    hdrs = {"Accept": "application/json"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = Request(url, data=body, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8") or "{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error": raw}
        return exc.code, payload
    except URLError as exc:
        return 0, {"error": str(exc.reason)}
