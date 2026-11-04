"""End-to-end smoke tests for AegisGrid."""

from __future__ import annotations

import json
from pathlib import Path

from core import (
    AegisGrid,
    MANIFEST_FILENAME,
    ManifestService,
    NetworkGuard,
    restore_network_guard,
)


def test_full_operational_smoke(tmp_path: Path):
    NetworkGuard.release()
    restore_network_guard()

    hmac_key = b"smoke-test-key"
    app_module = tmp_path / "app.py"
    app_module.write_text("print('ok')\n", encoding="utf-8")

    grid = AegisGrid(root_dir=tmp_path, hmac_key=hmac_key, install_guard=True)
    token = grid.generate_token()
    grid.register_operator_token(token, role="operator")

    assert grid.authenticate(token).authorized
    result = grid.set_temperature(token, 3.5)
    assert result.applied_c == 3.5
    assert not result.watchdog_override

    grid.ingest_threat("10.0.0.1", "scan", 6)
    assert len(grid.query_threats(min_severity=5)) == 1

    digest = grid.manifest.file_digest(app_module)
    payload = {
        "version": "1.0.0-smoke",
        "generated_at": "2026-11-04T00:00:00+00:00",
        "files": [{"path": "app.py", "sha256": digest}],
    }
    payload["signature"] = grid.manifest.sign_document_payload(payload)
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps(payload), encoding="utf-8")

    assert grid.run_integrity_check() is True
    assert not grid.network_locked()

    app_module.write_text("print('tampered')\n", encoding="utf-8")
    assert grid.run_integrity_check() is False
    assert grid.network_locked()
    assert "ok" in app_module.read_text(encoding="utf-8")

    grid.close()
