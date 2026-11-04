"""Unit tests for AegisGrid core."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

import core
from core import (
    AccessDeniedError,
    AegisGrid,
    ManifestVerificationError,
    NetworkGuard,
    NetworkLockdownError,
    TEMP_MAX_C,
    TEMP_MIN_C,
    WATCHDOG_SAFE_COMPRESSOR_ON,
    restore_network_guard,
)


@pytest.fixture(autouse=True)
def reset_network_guard():
    NetworkGuard.release()
    restore_network_guard()
    yield
    NetworkGuard.release()
    restore_network_guard()


@pytest.fixture
def tmp_grid(tmp_path: Path):
    grid = AegisGrid(root_dir=tmp_path, install_guard=True)
    token = "test-operator-token"
    grid.register_operator_token(token)
    yield grid, token
    grid.close()


def test_authenticate_valid_token(tmp_grid):
    grid, token = tmp_grid
    result = grid.authenticate(token)
    assert result.authorized is True
    assert result.role == "operator"
    assert len(result.token_hash) == 64


def test_authenticate_rejects_invalid_token(tmp_grid):
    grid, _ = tmp_grid
    result = grid.authenticate("not-a-real-token")
    assert result.authorized is False


def test_require_auth_raises_on_malicious_token(tmp_grid):
    grid, _ = tmp_grid
    with pytest.raises(AccessDeniedError):
        grid.set_temperature("'; DROP TABLE access_control; --", 4.0)


def test_set_temperature_success_within_bounds(tmp_grid):
    grid, token = tmp_grid
    outcome = grid.set_temperature(token, 4.5, compressor_on=True)
    assert outcome.applied_c == 4.5
    assert outcome.watchdog_override is False
    assert outcome.watchdog_active is False
    state = grid.read_temperature()
    assert state is not None
    assert state["temperature_c"] == 4.5
    assert state["compressor_on"] is True


def test_injection_below_min_triggers_watchdog(tmp_grid):
    grid, _ = tmp_grid
    outcome = grid.unsafe_injection_set_temperature(-10.0)
    assert outcome.watchdog_override is True
    assert outcome.watchdog_active is True
    assert outcome.applied_c == TEMP_MIN_C
    assert outcome.compressor_on is WATCHDOG_SAFE_COMPRESSOR_ON


def test_injection_above_max_triggers_watchdog(tmp_grid):
    grid, _ = tmp_grid
    outcome = grid.unsafe_injection_set_temperature(25.0)
    assert outcome.watchdog_override is True
    assert outcome.applied_c == TEMP_MAX_C
    assert outcome.compressor_on is WATCHDOG_SAFE_COMPRESSOR_ON


def test_authorized_request_outside_bounds_still_clamped(tmp_grid):
    grid, token = tmp_grid
    outcome = grid.set_temperature(token, 0.0)
    assert outcome.requested_c == 0.0
    assert outcome.applied_c == TEMP_MIN_C
    assert outcome.watchdog_override is True


def test_threat_ingestion_and_query(tmp_grid):
    grid, _ = tmp_grid
    grid.ingest_threat("192.0.2.10", "blocked_ip", 7)
    grid.ingest_threat("192.0.2.10", "blocked_ip", 9)
    grid.ingest_threat("malware.exe", "malware_hash", 5)

    all_high = grid.query_threats(min_severity=7)
    assert len(all_high) == 1
    assert all_high[0]["indicator"] == "192.0.2.10"
    assert all_high[0]["severity"] == 9

    exact = grid.query_threats(indicator="malware.exe")
    assert len(exact) == 1
    assert exact[0]["threat_type"] == "malware_hash"


def test_threat_severity_validation(tmp_grid):
    grid, _ = tmp_grid
    with pytest.raises(ValueError):
        grid.ingest_threat("x", "y", 11)


def _build_manifest(root: Path, hmac_key: bytes, files: dict[str, str]) -> None:
    entries = [{"path": rel, "sha256": digest} for rel, digest in files.items()]
    payload = {
        "version": "1.0.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "files": entries,
    }
    service = core.ManifestService(root, core.DuckDBEngine(root / "manifest_helper.duckdb"), hmac_key=hmac_key)
    payload["signature"] = service.sign_document_payload(payload)
    (root / core.MANIFEST_FILENAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    service.db.close()


def test_manifest_verification_passes(tmp_path: Path):
    hmac_key = b"unit-test-hmac-key"
    target = tmp_path / "core.py"
    target.write_text("# pristine\n", encoding="utf-8")
    digest = core.ManifestService(
        tmp_path,
        core.DuckDBEngine(tmp_path / "m1.duckdb"),
        hmac_key=hmac_key,
    ).file_digest(target)
    _build_manifest(tmp_path, hmac_key, {"core.py": digest})

    grid = AegisGrid(root_dir=tmp_path, hmac_key=hmac_key, install_guard=True)
    assert grid.run_integrity_check() is True
    assert grid.network_locked() is False
    grid.close()


def test_manifest_tamper_triggers_rollback_and_lockdown(tmp_path: Path):
    hmac_key = b"unit-test-hmac-key"
    target = tmp_path / "core.py"
    target.write_text("# pristine\n", encoding="utf-8")
    manifest_service = core.ManifestService(
        tmp_path,
        core.DuckDBEngine(tmp_path / "m2.duckdb"),
        hmac_key=hmac_key,
    )
    digest = manifest_service.file_digest(target)
    manifest_service.snapshot_backups(["core.py"])
    _build_manifest(tmp_path, hmac_key, {"core.py": digest})
    manifest_service.db.close()

    target.write_text("# TAMPERED\n", encoding="utf-8")

    grid = AegisGrid(root_dir=tmp_path, hmac_key=hmac_key, install_guard=True)
    assert grid.run_integrity_check() is False
    assert grid.network_locked() is True
    assert target.read_text(encoding="utf-8") == "# pristine\n"

    with pytest.raises(NetworkLockdownError):
        socket.socket()

    grid.close()


def test_manifest_bad_signature_rejected(tmp_path: Path):
    hmac_key = b"unit-test-hmac-key"
    bad = {
        "version": "1.0.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "files": [],
        "signature": "deadbeef",
    }
    (tmp_path / core.MANIFEST_FILENAME).write_text(json.dumps(bad), encoding="utf-8")
    grid = AegisGrid(root_dir=tmp_path, hmac_key=hmac_key, install_guard=True)
    with pytest.raises(ManifestVerificationError):
        grid.run_integrity_check()
    grid.close()


def test_hardware_watchdog_direct():
    wd = core.HardwareWatchdog()
    temp, comp, override = wd.evaluate(4.0, False)
    assert temp == 4.0
    assert comp is False
    assert override is False

    temp, comp, override = wd.evaluate(12.0, False)
    assert temp == TEMP_MAX_C
    assert comp is WATCHDOG_SAFE_COMPRESSOR_ON
    assert override is True
    assert wd.active is True
