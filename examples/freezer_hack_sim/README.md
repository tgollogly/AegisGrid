# Freezer hack simulation (localhost)

## Legal disclaimer

This repository includes a **software simulation** and an **untested concept** for learning and research only. It is **not** a certified safety or security device. **Do not** connect it to real refrigeration controllers, food storage, or any safety-critical or live equipment.

Nothing is unhackable, and no protection is guaranteed. The software is provided **as is**, with **no warranty**, under the [MIT licence](../../LICENSE). The author accepts **no liability** for any loss, damage, food spoilage, or harm arising from its use or misuse.

Users are responsible for following applicable laws, food-safety rules, and manufacturer guidance. Product and trademark names mentioned in this repository belong to their owners; there is no affiliation, endorsement, or official connection.

See also [DISCLAIMER.md](../../DISCLAIMER.md).

---

Toy Python simulation of a supermarket-style freezer controller on **127.0.0.1**, a weak default password, an attacker-style script built into `simulation.py`, and a **guard proxy** that enforces a staff token, freezer temperature bounds **−25 °C to −15 °C**, trip behaviour, and a simulated SMS log line.

It illustrates the pattern behind AegisGrid (tokens, bounds, fail-closed) without using the DuckDB engine in `core.py`.

**Context (Oct–Nov 2026):** Reports described internet-exposed refrigeration controllers in Europe targeted with default passwords and forced defrost toward ~50 °C ([BBC overview](https://www.bbc.com/news/articles/cq1kd1nee80eo)).

All HTTP stays on localhost. No external network.

## Run the full demo (table + chart)

From the repository root, with an optional matplotlib install for chart output:

```bash
pip install matplotlib   # only needed to regenerate the chart locally
python -m examples.freezer_hack_sim.simulation
```

Outputs (gitignored): `results.txt`, `results.json`, `results.png` in this folder. A reference chart is checked in at [`assets/freezer-hack-sim-results.png`](../../assets/freezer-hack-sim-results.png).

## Run tests only

From the repository root (no matplotlib required):

```bash
pip install -e ".[dev]"
python -m pytest tests/test_freezer_hack_sim.py -q
```

## Honest limits

Simulation only — not real Danfoss hardware, not a real OT protocol, and **not** proof of real-world security. The staff “VPN” is an HTTP header, the temperature model is linear and approximate, and physical access or bugs in the guard code are out of scope.
