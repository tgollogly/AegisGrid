# Quick start (about 5 minutes)

AegisGrid is **free and open source** ([MIT License](LICENSE)). It helps you experiment with **local** refrigeration/IoT gateway patterns: access control, temperature safety bounds, audit logs, and file integrity checks. It is a **reference implementation** — not certified safety hardware. Read the [Legal disclaimer](DISCLAIMER.md) before production use.

## 1. Install

```bash
git clone https://github.com/tgollogly/AegisGrid.git
cd AegisGrid
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .            # installs the `aegisgrid` command
```

Requires **Python 3.11+**. No cloud account, no API keys, no AI services.

## 2. Initialize (one command)

```bash
aegisgrid init
```

This creates `aegis_local.duckdb` and saves your operator token to `.aegis_operator_token` (gitignored). **Treat that file like a password.**

## 3. Daily commands

```bash
# Current state
aegisgrid status

# Set temperature (safe range 1°C–8°C; watchdog clamps out-of-range values)
aegisgrid temperature set --value 4.0

# Add a local threat indicator (offline blocklist / intel cache)
aegisgrid threat add --indicator 203.0.113.50 --type blocked_ip --severity 8
aegisgrid threat list --min-severity 5
```

## 4. Integrity manifest (optional, for updates)

After you trust your deployed files:

```bash
export AEGIS_MANIFEST_HMAC_KEY="$(openssl rand -hex 32)"   # production: store in secrets manager
aegisgrid manifest sign core.py cli.py
aegisgrid integrity check
```

If a tracked file is tampered with, AegisGrid restores from `.aegis_backup/` and turns on **network lockdown** (new sockets blocked).

## 5. Run the demo script

```bash
bash examples/first_run.sh
```

## 6. Python API (if you embed AegisGrid)

```python
from core import AegisGrid

with AegisGrid(root_dir=".") as grid:
    token = grid.generate_token()
    grid.register_operator_token(token)
    print(grid.set_temperature(token, 4.0))
```

## What this does **not** do

- It does **not** guarantee that hackers cannot attack your network or device.
- It does **not** replace physical thermal cut-outs or professional engineering sign-off.
- It does **not** provide legal or food-safety advice.

It **does** give you a clear, testable starting point for **offline-first** control and audit on a gateway.

## Help

```bash
aegisgrid --help
aegisgrid temperature set --help
```

More detail: [README.md](README.md) · LinkedIn banner: [assets/aegisgrid-hero-banner.jpg](assets/aegisgrid-hero-banner.jpg) · Tests: `python3 -m pytest -q`
