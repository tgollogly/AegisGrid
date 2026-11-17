# Changelog

## [1.0.0] — 2026-11-17

First sealed GitHub Release of AegisGrid.

- **Core** — Local DuckDB refrigeration gateway security reference (`core.py`, `cli.py`): tokens, audit, temperature bounds, manifest integrity, and lockdown on tamper.
- **CLI** — `aegisgrid` entry point with `init`, `status`, `temperature set`, `threat`, `manifest sign`, and `integrity check`.
- **Examples** — `examples/first_run.sh` and localhost `examples/freezer_hack_sim/` simulation with tests.
- **Docs** — README, QUICKSTART, WHY, BUILD_GUIDE, DISCLAIMER, and brand assets.
- **CI** — Python 3.11/3.12 test matrix, CodeQL, and security automation.
- **Release** — Tag-triggered GitHub Release with sdist, wheel, source zip, `SHA256SUMS.txt`, and build provenance attestations.