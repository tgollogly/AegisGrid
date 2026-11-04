"""
AegisGrid command-line interface.

Copyright (c) 2026 tgollogly. SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from core import (
    AegisGrid,
    AccessDeniedError,
    MANIFEST_FILENAME,
    ManifestVerificationError,
    configure_logging,
)

DEFAULT_TOKEN_FILE = ".aegis_operator_token"


def _open_grid(root: Path) -> AegisGrid:
    return AegisGrid(root_dir=root, install_guard=True)


def _token_path(args: argparse.Namespace) -> Path:
    raw = Path(args.token_file)
    if raw.is_absolute():
        return raw
    root = Path(args.root).resolve()
    return root / raw


def _read_token(args: argparse.Namespace) -> str:
    if getattr(args, "token", None):
        return args.token.strip()
    token_path = _token_path(args)
    if not token_path.is_file():
        print(
            "Missing operator token. Run:  aegisgrid init\n"
            f"Or pass --token or --token-file (default under --root: {DEFAULT_TOKEN_FILE})",
            file=sys.stderr,
        )
        sys.exit(2)
    return token_path.read_text(encoding="utf-8").strip()


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    tf = Path(args.token_file)
    token_path = tf if tf.is_absolute() else root / tf

    with _open_grid(root) as grid:
        token = grid.generate_token()
        grid.register_operator_token(token, role="operator")
        if args.save_token:
            token_path.write_text(token + "\n", encoding="utf-8")
            try:
                os.chmod(token_path, 0o600)
            except OSError:
                pass

    print("AegisGrid initialized.")
    print(f"  Root:     {root}")
    print(f"  Database: {root / 'aegis_local.duckdb'}")
    if args.save_token:
        print(f"  Token saved to {token_path} (keep secret; gitignored)")
    else:
        print(f"  Operator token (copy and store safely): {token}")
    print("\nNext:")
    print("  aegisgrid status")
    print("  aegisgrid temperature set --value 4.0")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    with _open_grid(root) as grid:
        state = grid.read_temperature()
        locked = grid.network_locked()
    print(f"Root: {root}")
    print(f"Network lockdown: {'ACTIVE' if locked else 'off'}")
    if state is None:
        print("Hardware state: (none yet — set a temperature to create the ledger)")
    else:
        print(f"Temperature: {state['temperature_c']}°C")
        print(f"Compressor:  {'on' if state['compressor_on'] else 'off'}")
        print(f"Watchdog:    {'active' if state['watchdog_active'] else 'idle'}")
    return 0


def cmd_token_create(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    with _open_grid(root) as grid:
        token = grid.generate_token()
        grid.register_operator_token(token, role=args.role)
    print(token)
    return 0


def cmd_temperature_set(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    token = _read_token(args)
    with _open_grid(root) as grid:
        try:
            result = grid.set_temperature(
                token,
                float(args.value),
                compressor_on=not args.compressor_off,
            )
        except AccessDeniedError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    print(f"Requested: {result.requested_c}°C  Applied: {result.applied_c}°C")
    if result.watchdog_override:
        print("Safety watchdog: value clamped to 1°C–8°C")
    return 0


def cmd_threat_add(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    with _open_grid(root) as grid:
        grid.ingest_threat(args.indicator, args.type, int(args.severity))
    print("Threat recorded in local DuckDB cache.")
    return 0


def cmd_threat_list(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    with _open_grid(root) as grid:
        rows = grid.query_threats(
            indicator=args.indicator,
            min_severity=int(args.min_severity) if args.min_severity is not None else None,
        )
    if not rows:
        print("No matching threats.")
        return 0
    for row in rows:
        print(f"{row['severity']:2d}  {row['threat_type']:16s}  {row['indicator']}")
    return 0


def cmd_integrity_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    manifest = Path(args.manifest).resolve() if args.manifest else None
    with _open_grid(root) as grid:
        try:
            ok = grid.run_integrity_check(manifest)
        except ManifestVerificationError as exc:
            print(f"Integrity check failed: {exc}", file=sys.stderr)
            return 1
    if ok:
        print("Integrity check: OK")
        return 0
    print("Tamper detected: files restored from backup; network lockdown is ON")
    return 1


def cmd_manifest_sign(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    paths = [Path(p) for p in args.paths]
    for p in paths:
        resolved = p if p.is_absolute() else root / p
        if not resolved.is_file():
            print(f"Not a file: {resolved}", file=sys.stderr)
            return 1

    with _open_grid(root) as grid:
        entries = []
        for p in paths:
            resolved = p if p.is_absolute() else root / p
            rel = resolved.resolve().relative_to(root)
            digest = grid.manifest.file_digest(resolved.resolve())
            entries.append({"path": rel.as_posix(), "sha256": digest})
        payload: dict[str, object] = {
            "version": args.version,
            "generated_at": args.generated_at or datetime.now(timezone.utc).isoformat(),
            "files": entries,
        }
        payload["signature"] = grid.manifest.sign_document_payload(payload)
        out = root / args.output
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    print("Verify with:  aegisgrid integrity check")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisgrid",
        description="AegisGrid — free, local IoT refrigeration control & audit (MIT License)",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Project/appliance root directory (default: current directory)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize database and create first operator token")
    p_init.add_argument(
        "--token-file",
        default=DEFAULT_TOKEN_FILE,
        help=f"Where to save operator token (default: {DEFAULT_TOKEN_FILE})",
    )
    p_init.add_argument(
        "--no-save-token",
        dest="save_token",
        action="store_false",
        help="Print token once instead of writing a file",
    )
    p_init.set_defaults(save_token=True, func=cmd_init)

    p_status = sub.add_parser("status", help="Show lockdown flag and latest temperature state")
    p_status.set_defaults(func=cmd_status)

    p_tok = sub.add_parser("token", help="Manage access tokens")
    tok_sub = p_tok.add_subparsers(dest="token_cmd", required=True)
    p_tok_create = tok_sub.add_parser("create", help="Register a new operator token (prints token)")
    p_tok_create.add_argument("--role", default="operator")
    p_tok_create.set_defaults(func=cmd_token_create)

    p_temp = sub.add_parser("temperature", help="Read or set appliance temperature (authorized)")
    temp_sub = p_temp.add_subparsers(dest="temp_cmd", required=True)
    p_temp_set = temp_sub.add_parser("set", help="Set target temperature in °C (1–8 enforced)")
    p_temp_set.add_argument("--value", required=True, help="Requested temperature in °C")
    p_temp_set.add_argument("--token", help="Operator token (or use token file)")
    p_temp_set.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    p_temp_set.add_argument("--compressor-off", action="store_true", help="Request compressor off")
    p_temp_set.set_defaults(func=cmd_temperature_set)

    p_threat = sub.add_parser("threat", help="Local threat intelligence cache (DuckDB)")
    threat_sub = p_threat.add_subparsers(dest="threat_cmd", required=True)
    p_threat_add = threat_sub.add_parser("add", help="Add or update a threat indicator")
    p_threat_add.add_argument("--indicator", required=True)
    p_threat_add.add_argument("--type", required=True, dest="type")
    p_threat_add.add_argument("--severity", required=True, type=int, help="0–10")
    p_threat_add.set_defaults(func=cmd_threat_add)
    p_threat_list = threat_sub.add_parser("list", help="List cached threats")
    p_threat_list.add_argument("--indicator")
    p_threat_list.add_argument("--min-severity", type=int)
    p_threat_list.set_defaults(func=cmd_threat_list)

    p_int = sub.add_parser("integrity", help="Signed manifest verification")
    int_sub = p_int.add_subparsers(dest="int_cmd", required=True)
    p_int_check = int_sub.add_parser("check", help="Verify files against aegis_manifest.json")
    p_int_check.add_argument("--manifest", help=f"Manifest path (default: ./{MANIFEST_FILENAME})")
    p_int_check.set_defaults(func=cmd_integrity_check)

    p_man = sub.add_parser("manifest", help="Build signed integrity manifest")
    man_sub = p_man.add_subparsers(dest="man_cmd", required=True)
    p_man_sign = man_sub.add_parser("sign", help="Hash files and write signed manifest")
    p_man_sign.add_argument("paths", nargs="+", help="Files to include (paths relative to --root)")
    p_man_sign.add_argument("--output", default=MANIFEST_FILENAME)
    p_man_sign.add_argument("--version", default="1.0.0")
    p_man_sign.add_argument("--generated-at", default=None)
    p_man_sign.set_defaults(func=cmd_manifest_sign)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verbose:
        import logging

        configure_logging(logging.DEBUG)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
