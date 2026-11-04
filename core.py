"""
AegisGrid — local IoT refrigeration control, threat intelligence, and audit core.

Copyright (c) 2026 tgollogly. SPDX-License-Identifier: MIT.
See LICENSE and DISCLAIMER.md.

All state is persisted in DuckDB. Network egress is gated by an explicit lockdown flag
that rejects socket creation when tamper or manifest verification fails.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import duckdb

__all__ = [
    "AegisGrid",
    "AccessDeniedError",
    "HardwareWatchdog",
    "ManifestVerificationError",
    "NetworkLockdownError",
    "NetworkGuard",
    "TEMP_MAX_C",
    "TEMP_MIN_C",
    "WATCHDOG_SAFE_COMPRESSOR_ON",
]

LOG = logging.getLogger("aegisgrid")

TEMP_MIN_C: float = 1.0
TEMP_MAX_C: float = 8.0
WATCHDOG_SAFE_COMPRESSOR_ON: bool = True

DEFAULT_DB_FILENAME = "aegis_local.duckdb"
MANIFEST_FILENAME = "aegis_manifest.json"
BACKUP_DIRNAME = ".aegis_backup"
MANIFEST_HMAC_KEY_ENV = "AEGIS_MANIFEST_HMAC_KEY"


class AegisGridError(Exception):
    """Base error for AegisGrid operations."""


class AccessDeniedError(AegisGridError):
    """Raised when cryptographic access control rejects a credential."""


class ManifestVerificationError(AegisGridError):
    """Raised when manifest verification or rollback fails irrecoverably."""


class NetworkLockdownError(AegisGridError):
    """Raised when network operations are blocked by lockdown policy."""


class TemperatureSafetyError(AegisGridError):
    """Raised when temperature cannot be applied even after watchdog handling."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_token(token: str) -> str:
    return token.strip()


@dataclass(frozen=True)
class AuthResult:
    authorized: bool
    token_hash: str
    role: str | None = None


@dataclass(frozen=True)
class TemperatureCommandResult:
    requested_c: float
    applied_c: float
    watchdog_override: bool
    compressor_on: bool
    watchdog_active: bool


@dataclass(frozen=True)
class ManifestEntry:
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class ManifestDocument:
    version: str
    generated_at: str
    files: tuple[ManifestEntry, ...]
    signature: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ManifestDocument:
        files_raw = data.get("files")
        if not isinstance(files_raw, list):
            raise ManifestVerificationError("Manifest 'files' must be a list")
        files: list[ManifestEntry] = []
        for item in files_raw:
            if not isinstance(item, dict):
                raise ManifestVerificationError("Each manifest file entry must be an object")
            rel = item.get("path")
            digest = item.get("sha256")
            if not isinstance(rel, str) or not isinstance(digest, str):
                raise ManifestVerificationError("Manifest entries require string path and sha256")
            files.append(ManifestEntry(relative_path=rel, sha256=digest.lower()))
        version = data.get("version")
        generated_at = data.get("generated_at")
        signature = data.get("signature")
        if not isinstance(version, str) or not isinstance(generated_at, str) or not isinstance(signature, str):
            raise ManifestVerificationError("Manifest missing version, generated_at, or signature")
        return cls(
            version=version,
            generated_at=generated_at,
            files=tuple(files),
            signature=signature,
        )


class NetworkGuard:
    """Process-wide network lockdown gate for socket creation."""

    _locked: bool = False
    _reason: str | None = None

    @classmethod
    def is_locked(cls) -> bool:
        return cls._locked

    @classmethod
    def lock_reason(cls) -> str | None:
        return cls._reason

    @classmethod
    def engage(cls, reason: str) -> None:
        cls._locked = True
        cls._reason = reason
        LOG.critical("Network lockdown engaged: %s", reason)

    @classmethod
    def release(cls) -> None:
        cls._locked = False
        cls._reason = None
        LOG.info("Network lockdown released")

    @classmethod
    def assert_allowed(cls) -> None:
        if cls._locked:
            raise NetworkLockdownError(
                f"Network access denied (lockdown active): {cls._reason or 'unspecified'}"
            )


_original_socket = socket.socket


def _guarded_socket(family: int = socket.AF_INET, type: int = socket.SOCK_STREAM, proto: int = 0, fileno: int | None = None):
    NetworkGuard.assert_allowed()
    if fileno is not None:
        return _original_socket(family, type, proto, fileno)
    return _original_socket(family, type, proto)


def install_network_guard() -> None:
    if socket.socket is not _guarded_socket:
        socket.socket = _guarded_socket  # type: ignore[assignment]


def restore_network_guard() -> None:
    socket.socket = _original_socket  # type: ignore[assignment]


class HardwareWatchdog:
    """
    Software model of a hardware watchdog that overrides unsafe compressor commands.

    When temperature leaves [TEMP_MIN_C, TEMP_MAX_C], the watchdog forces the compressor
    to WATCHDOG_SAFE_COMPRESSOR_ON regardless of software intent.
    """

    def __init__(self) -> None:
        self._active = False
        self._last_reason: str | None = None

    @property
    def active(self) -> bool:
        return self._active

    @property
    def last_reason(self) -> str | None:
        return self._last_reason

    def evaluate(self, temperature_c: float, requested_compressor_on: bool) -> tuple[float, bool, bool]:
        """
        Returns (safe_temperature_c, compressor_on, watchdog_override_applied).
        """
        override = False
        safe_temp = temperature_c

        if temperature_c < TEMP_MIN_C:
            self._active = True
            self._last_reason = f"temperature {temperature_c}°C below minimum {TEMP_MIN_C}°C"
            safe_temp = TEMP_MIN_C
            override = True
        elif temperature_c > TEMP_MAX_C:
            self._active = True
            self._last_reason = f"temperature {temperature_c}°C above maximum {TEMP_MAX_C}°C"
            safe_temp = TEMP_MAX_C
            override = True
        else:
            self._active = False
            self._last_reason = None

        if self._active:
            compressor_on = WATCHDOG_SAFE_COMPRESSOR_ON
            override = True
        else:
            compressor_on = requested_compressor_on

        return safe_temp, compressor_on, override


class DuckDBEngine:
    """Local DuckDB persistence for threat cache, hardware ledger, and access control."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self.db_path))
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self._conn.execute("BEGIN TRANSACTION")
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def _init_schema(self) -> None:
        sequences = (
            "seq_access_control",
            "seq_threat_cache",
            "seq_hardware_state",
            "seq_system_audit",
        )
        for seq in sequences:
            self._conn.execute(f"CREATE SEQUENCE IF NOT EXISTS {seq} START 1")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_control (
                id BIGINT PRIMARY KEY DEFAULT nextval('seq_access_control'),
                token_hash VARCHAR NOT NULL UNIQUE,
                role VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL
            );
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_cache (
                id BIGINT PRIMARY KEY DEFAULT nextval('seq_threat_cache'),
                indicator VARCHAR NOT NULL,
                threat_type VARCHAR NOT NULL,
                severity INTEGER NOT NULL,
                ingested_at TIMESTAMP NOT NULL,
                UNIQUE(indicator, threat_type)
            );
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hardware_state (
                id BIGINT PRIMARY KEY DEFAULT nextval('seq_hardware_state'),
                recorded_at TIMESTAMP NOT NULL,
                temperature_c DOUBLE NOT NULL,
                compressor_on BOOLEAN NOT NULL,
                watchdog_active BOOLEAN NOT NULL,
                watchdog_override BOOLEAN NOT NULL,
                actor_token_hash VARCHAR,
                note VARCHAR
            );
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_audit (
                id BIGINT PRIMARY KEY DEFAULT nextval('seq_system_audit'),
                recorded_at TIMESTAMP NOT NULL,
                event_type VARCHAR NOT NULL,
                detail VARCHAR NOT NULL
            );
            """
        )

    def audit(self, event_type: str, detail: str) -> None:
        self._conn.execute(
            "INSERT INTO system_audit (recorded_at, event_type, detail) VALUES (?, ?, ?)",
            [utc_now(), event_type, detail],
        )

    def add_authorized_token(self, token: str, role: str = "operator") -> str:
        token_hash = sha256_hex(normalize_token(token))
        self._conn.execute(
            """
            INSERT INTO access_control (token_hash, role, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT (token_hash) DO UPDATE SET role = excluded.role
            """,
            [token_hash, role, utc_now()],
        )
        return token_hash

    def remove_token_hash(self, token_hash: str) -> None:
        self._conn.execute("DELETE FROM access_control WHERE token_hash = ?", [token_hash])

    def authenticate(self, token: str) -> AuthResult:
        token_hash = sha256_hex(normalize_token(token))
        row = self._conn.execute(
            "SELECT role FROM access_control WHERE token_hash = ?",
            [token_hash],
        ).fetchone()
        if row is None:
            self.audit("auth_failure", f"rejected token hash prefix {token_hash[:12]}")
            return AuthResult(authorized=False, token_hash=token_hash)
        role = row[0]
        self.audit("auth_success", f"role={role} hash prefix {token_hash[:12]}")
        return AuthResult(authorized=True, token_hash=token_hash, role=str(role))

    def ingest_threat(self, indicator: str, threat_type: str, severity: int) -> None:
        if severity < 0 or severity > 10:
            raise ValueError("severity must be between 0 and 10")
        self._conn.execute(
            """
            INSERT INTO threat_cache (indicator, threat_type, severity, ingested_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (indicator, threat_type) DO UPDATE SET
                severity = excluded.severity,
                ingested_at = excluded.ingested_at
            """,
            [indicator.strip(), threat_type.strip(), severity, utc_now()],
        )

    def query_threats(
        self,
        indicator: str | None = None,
        min_severity: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if indicator is not None:
            clauses.append("indicator = ?")
            params.append(indicator.strip())
        if min_severity is not None:
            clauses.append("severity >= ?")
            params.append(min_severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"""
            SELECT indicator, threat_type, severity, ingested_at
            FROM threat_cache
            {where}
            ORDER BY severity DESC, ingested_at DESC
            """,
            params,
        ).fetchall()
        return [
            {
                "indicator": r[0],
                "threat_type": r[1],
                "severity": r[2],
                "ingested_at": r[3],
            }
            for r in rows
        ]

    def append_hardware_state(
        self,
        temperature_c: float,
        compressor_on: bool,
        watchdog_active: bool,
        watchdog_override: bool,
        actor_token_hash: str | None = None,
        note: str | None = None,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO hardware_state (
                recorded_at, temperature_c, compressor_on,
                watchdog_active, watchdog_override, actor_token_hash, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                utc_now(),
                temperature_c,
                compressor_on,
                watchdog_active,
                watchdog_override,
                actor_token_hash,
                note,
            ],
        )

    def latest_hardware_state(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT recorded_at, temperature_c, compressor_on, watchdog_active,
                   watchdog_override, actor_token_hash, note
            FROM hardware_state
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return {
            "recorded_at": row[0],
            "temperature_c": row[1],
            "compressor_on": row[2],
            "watchdog_active": row[3],
            "watchdog_override": row[4],
            "actor_token_hash": row[5],
            "note": row[6],
        }


class ManifestService:
    """Signed manifest verification, backup, rollback, and lockdown orchestration."""

    def __init__(
        self,
        root_dir: Path,
        db: DuckDBEngine,
        hmac_key: bytes | None = None,
    ) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.db = db
        self.backup_dir = self.root_dir / BACKUP_DIRNAME
        env_key = os.environ.get(MANIFEST_HMAC_KEY_ENV)
        if hmac_key is not None:
            self._hmac_key = hmac_key
        elif env_key:
            self._hmac_key = env_key.encode("utf-8")
        else:
            self._hmac_key = b"aegisgrid-local-dev-key-change-in-production"

    def _payload_bytes(self, doc: Mapping[str, Any]) -> bytes:
        payload = {
            "version": doc["version"],
            "generated_at": doc["generated_at"],
            "files": doc["files"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_document_payload(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(self._hmac_key, self._payload_bytes(payload), hashlib.sha256).hexdigest()

    def load_manifest(self, manifest_path: Path | None = None) -> ManifestDocument:
        path = manifest_path or (self.root_dir / MANIFEST_FILENAME)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ManifestVerificationError(f"Manifest not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ManifestVerificationError(f"Invalid manifest JSON: {path}") from exc
        if not isinstance(raw, dict):
            raise ManifestVerificationError("Manifest root must be a JSON object")
        doc = ManifestDocument.from_mapping(raw)
        expected_sig = self.sign_document_payload(raw)
        if not hmac.compare_digest(doc.signature, expected_sig):
            raise ManifestVerificationError("Manifest HMAC signature mismatch")
        return doc

    def file_digest(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def snapshot_backups(self, relative_paths: Sequence[str]) -> None:
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        for rel in relative_paths:
            src = self.root_dir / rel
            if not src.is_file():
                continue
            dest = self.backup_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    def rollback_files(self, relative_paths: Sequence[str]) -> list[str]:
        restored: list[str] = []
        for rel in relative_paths:
            backup = self.backup_dir / rel
            target = self.root_dir / rel
            if not backup.is_file():
                LOG.error("Rollback missing backup for %s", rel)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, target)
            restored.append(rel)
        return restored

    def verify_and_heal(self, manifest_path: Path | None = None) -> bool:
        """
        Verify tracked files against the signed manifest.

        Returns True if all hashes match. On any mismatch, rolls back from backup,
        records audit events, and engages network lockdown.
        """
        doc = self.load_manifest(manifest_path)
        rel_paths = [e.relative_path for e in doc.files]

        mismatches: list[str] = []
        for entry in doc.files:
            target = self.root_dir / entry.relative_path
            if not target.is_file():
                mismatches.append(f"{entry.relative_path} (missing)")
                continue
            digest = self.file_digest(target)
            if digest.lower() != entry.sha256.lower():
                mismatches.append(f"{entry.relative_path} (expected {entry.sha256}, got {digest})")

        if not mismatches:
            self.snapshot_backups(rel_paths)
            self.db.audit("manifest_ok", f"version={doc.version} files={len(doc.files)}")
            return True

        detail = "; ".join(mismatches)
        self.db.audit("manifest_tamper", detail)
        restored = self.rollback_files(rel_paths)
        self.db.audit("manifest_rollback", f"restored={restored}")
        NetworkGuard.engage(f"manifest tamper detected: {detail}")
        still_bad: list[str] = []
        for entry in doc.files:
            target = self.root_dir / entry.relative_path
            if not target.is_file():
                still_bad.append(entry.relative_path)
                continue
            if self.file_digest(target).lower() != entry.sha256.lower():
                still_bad.append(entry.relative_path)
        if still_bad:
            raise ManifestVerificationError(
                f"Rollback completed but checksums still invalid for: {still_bad}"
            )
        return False


class AegisGrid:
    """Primary application facade for refrigeration control and local security."""

    def __init__(
        self,
        root_dir: Path | str | None = None,
        db_path: Path | str | None = None,
        hmac_key: bytes | None = None,
        install_guard: bool = True,
    ) -> None:
        self.root_dir = Path(root_dir or Path.cwd()).resolve()
        db_default = self.root_dir / DEFAULT_DB_FILENAME
        self.db = DuckDBEngine(Path(db_path) if db_path else db_default)
        self.watchdog = HardwareWatchdog()
        self.manifest = ManifestService(self.root_dir, self.db, hmac_key=hmac_key)
        if install_guard:
            install_network_guard()

    def close(self) -> None:
        self.db.close()

    def register_operator_token(self, token: str, role: str = "operator") -> str:
        return self.db.add_authorized_token(token, role=role)

    def authenticate(self, token: str) -> AuthResult:
        return self.db.authenticate(token)

    def require_auth(self, token: str) -> AuthResult:
        result = self.authenticate(token)
        if not result.authorized:
            raise AccessDeniedError("Invalid or unauthorized access token")
        return result

    def ingest_threat(self, indicator: str, threat_type: str, severity: int) -> None:
        self.db.ingest_threat(indicator, threat_type, severity)

    def query_threats(
        self,
        indicator: str | None = None,
        min_severity: int | None = None,
    ) -> list[dict[str, Any]]:
        return self.db.query_threats(indicator=indicator, min_severity=min_severity)

    def set_temperature(
        self,
        token: str,
        requested_c: float,
        compressor_on: bool = True,
    ) -> TemperatureCommandResult:
        auth = self.require_auth(token)
        return self._apply_temperature(
            requested_c=requested_c,
            compressor_on=compressor_on,
            actor_token_hash=auth.token_hash,
            note="authorized set_temperature",
        )

    def _apply_temperature(
        self,
        requested_c: float,
        compressor_on: bool,
        actor_token_hash: str | None,
        note: str,
    ) -> TemperatureCommandResult:
        safe_temp, safe_compressor, override = self.watchdog.evaluate(requested_c, compressor_on)
        self.db.append_hardware_state(
            temperature_c=safe_temp,
            compressor_on=safe_compressor,
            watchdog_active=self.watchdog.active,
            watchdog_override=override,
            actor_token_hash=actor_token_hash,
            note=note,
        )
        if override:
            self.db.audit(
                "watchdog_override",
                f"requested={requested_c} applied={safe_temp} compressor={safe_compressor}",
            )
        return TemperatureCommandResult(
            requested_c=requested_c,
            applied_c=safe_temp,
            watchdog_override=override,
            compressor_on=safe_compressor,
            watchdog_active=self.watchdog.active,
        )

    def unsafe_injection_set_temperature(self, requested_c: float) -> TemperatureCommandResult:
        """
        Simulates a malicious local write bypassing auth; watchdog still enforces bounds.
        """
        return self._apply_temperature(
            requested_c=requested_c,
            compressor_on=True,
            actor_token_hash=None,
            note="injection_attempt",
        )

    def read_temperature(self) -> dict[str, Any] | None:
        return self.db.latest_hardware_state()

    def run_integrity_check(self, manifest_path: Path | None = None) -> bool:
        return self.manifest.verify_and_heal(manifest_path)

    def network_locked(self) -> bool:
        return NetworkGuard.is_locked()

    @staticmethod
    def generate_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def main() -> None:
    configure_logging()
    grid = AegisGrid(install_guard=True)
    LOG.info(
        "AegisGrid initialized db=%s lockdown=%s",
        grid.db.db_path,
        grid.network_locked(),
    )
    grid.close()


if __name__ == "__main__":
    main()
