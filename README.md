![AegisGrid Hero Banner — free MIT open source local IoT refrigeration control](assets/aegisgrid-hero-banner.jpg)

# AegisGrid

[![CI](https://github.com/tgollogly/AegisGrid/actions/workflows/ci.yml/badge.svg)](https://github.com/tgollogly/AegisGrid/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Free, open-source (MIT)** local control and audit for IoT refrigeration gateways — DuckDB storage, operator tokens, temperature safety bounds, and signed file integrity. **No cloud AI · no paid tier · no account.**

| | |
|---|---|
| **Why this exists** | **[WHY.md](WHY.md)** — voluntary, free, cold-chain defence |
| **Start here** | **[QUICKSTART.md](QUICKSTART.md)** (~5 min) |
| **Brand assets** | **[assets/README.md](assets/README.md)** · [hero banner](assets/aegisgrid-hero-banner.jpg) |
| **Legal** | [LICENSE](LICENSE) · [DISCLAIMER.md](DISCLAIMER.md) |

> **Honest scope:** Reference implementation with automated tests. Helps with **local** access control, auditing, and tamper-response **modelling** — not a guarantee against attackers, and **not** a substitute for certified hardware safety or professional sign-off.

---

## Why AegisGrid

Created **voluntarily** and shared **free (MIT)** so small sites — shops, kitchens, labs — are not priced out of basic **refrigeration gateway** security. Food resilience depends on **cold storage**; connected chillers and monitors can be **misconfigured or targeted** like any other IoT/OT kit. AegisGrid offers **offline-first** patterns (tokens, audit, temperature bounds, integrity checks) you can study and adapt alongside real hardware safeguards. Full narrative: **[WHY.md](WHY.md)**.

---

## Features

| Capability | Description |
|------------|-------------|
| **CLI (`aegisgrid`)** | `init`, `status`, `temperature set`, `threat`, `integrity check`, `manifest sign` |
| **Local DuckDB engine** | Threat cache, hardware state ledger, and audit log in `aegis_local.duckdb` |
| **Temperature safety** | Hard limits **1°C – 8°C** with watchdog override of compressor state |
| **Access control** | SHA-256 hashed tokens; unauthorized commands are rejected and audited |
| **Integrity & lockdown** | HMAC-signed manifest verification, rollback from `.aegis_backup/`, socket lockdown on tamper |
| **Offline-first** | No network required for normal operation |

---

## Requirements

- Python **3.11+**
- Linux or embedded Linux (developed on generic Linux)

---

## Installation

```bash
git clone https://github.com/tgollogly/AegisGrid.git
cd AegisGrid
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .    # installs `aegisgrid` on your PATH
```

Optional production secret for manifest signing:

```bash
export AEGIS_MANIFEST_HMAC_KEY="$(openssl rand -hex 32)"
```

---

## Quick start (CLI)

```bash
aegisgrid init
aegisgrid status
aegisgrid temperature set --value 4.0
aegisgrid threat add --indicator 203.0.113.1 --type blocked_ip --severity 7
aegisgrid threat list
```

Guided demo (uses a temporary directory):

```bash
bash examples/first_run.sh
```

Full walkthrough: **[QUICKSTART.md](QUICKSTART.md)**

### Quick start (Python API)

```python
from core import AegisGrid

with AegisGrid(root_dir=".") as grid:
    token = grid.generate_token()
    grid.register_operator_token(token)
    print(grid.set_temperature(token, requested_c=4.0))
```

---

## CLI reference

| Command | Purpose |
|---------|---------|
| `aegisgrid init` | Create DB + operator token (`.aegis_operator_token`) |
| `aegisgrid status` | Lockdown flag + latest temperature/compressor state |
| `aegisgrid token create` | Add another authorized token (prints once) |
| `aegisgrid temperature set --value °C` | Authorized set (watchdog enforces 1–8°C) |
| `aegisgrid threat add` / `list` | Local DuckDB threat cache |
| `aegisgrid manifest sign <files...>` | Build signed `aegis_manifest.json` |
| `aegisgrid integrity check` | Verify hashes; rollback + lockdown on tamper |

Global option: `--root /path/to/appliance` (default: current directory).

```bash
aegisgrid --help
```

If `aegisgrid` is not found after install, use `python3 -m cli` with the same arguments (e.g. `python3 -m cli init`).

---

## Architecture overview

AegisGrid uses a **local trust boundary**: the gateway hosts policy and data. When integrity verification fails, networking **fails closed** (new sockets blocked).

![AegisGrid architecture diagram — local zero-trust boundary](assets/aegisgrid-architecture.svg)

<details>
<summary>Mermaid source (for editors that render it)</summary>

```mermaid
flowchart TB
    subgraph LocalBoundary["Zero-trust local boundary"]
        UI["Operator / CLI"]
        AG["AegisGrid core"]
        WD["Hardware watchdog"]
        DB[("DuckDB aegis_local.duckdb")]
        MF["Signed manifest + backups"]
        NG["Network guard"]
    end
    UI -->|"SHA-256 token"| AG
    AG --> WD
    AG --> DB
    AG --> MF
    MF -->|tamper| NG
    NG -.->|blocks| Sockets["Socket creation"]
    WD -->|"1-8C clamp"| Compressor["Compressor safe default"]
```

</details>

**DuckDB tables:** `access_control`, `threat_cache`, `hardware_state`, `system_audit`

---

## Security hardening checklist

- Set `AEGIS_MANIFEST_HMAC_KEY` in production (not the dev default).
- Protect `.aegis_operator_token`; rotate with `aegisgrid token create`.
- Run as a dedicated OS user with minimal permissions.
- Schedule `aegisgrid integrity check` after updates (cron/systemd).
- Keep physical thermal hardware interlocks on real appliances.

---

## Testing

```bash
python3 -m pytest -q
```

CI runs the same suite on Python 3.11 and 3.12 (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).

---

## Troubleshooting

| Symptom | Action |
|---------|--------|
| `aegisgrid: command not found` | Run `pip install -e .` or use `python3 -m cli` |
| `AccessDeniedError` | Run `aegisgrid init` or pass a valid `--token` |
| Watchdog override in logs | Temperature was outside 1°C–8°C |
| `NetworkLockdownError` | Tamper detected — fix files/manifest/HMAC key |
| DuckDB locked | Only one process should open the DB |

```bash
duckdb aegis_local.duckdb "SELECT * FROM system_audit ORDER BY id DESC LIMIT 20;"
```

---

## FAQ

**Is it really free?**  
Yes. [MIT License](LICENSE) — use, modify, and share at no cost.

**Does it stop hackers?**  
No software can promise that. AegisGrid adds **local** controls and tamper response patterns; you still must harden the OS, network, and physical access.

**Does it need internet or AI?**  
No.

**Is it safety-certified?**  
No. See [DISCLAIMER.md](DISCLAIMER.md).

---

## License

Copyright (c) 2026 [tgollogly](https://github.com/tgollogly).

AegisGrid is released under the **[MIT License](LICENSE)** — free to use, modify, and distribute with attribution and licence text.

**Important:** The [Legal disclaimer](DISCLAIMER.md) applies to safety-critical and security-sensitive deployments. The MIT License does not replace your obligation to validate hardware interlocks, regulatory compliance, and operational procedures on target equipment.
