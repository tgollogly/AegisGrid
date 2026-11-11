# Untested concept: no-solder Raspberry Pi gateway

> **Disclaimer:** This is a software simulation and untested concept for learning and research only. It is not a certified safety or security device. Do not connect it to real refrigeration controllers, food storage, or any safety-critical or live equipment. Nothing is unhackable and no protection is guaranteed. Provided as is, with no warranty, under the MIT licence; the author accepts no liability for any loss, damage, food spoilage, or harm from its use or misuse. Users are responsible for following laws, food-safety rules and manufacturer guidance. Trademarks and product names belong to their owners; there is no affiliation. See also [DISCLAIMER.md](../DISCLAIMER.md).

**Status: untested concept only.** This note describes how someone might experiment with a **local** refrigeration gateway on spare hardware. It is **not** validated wiring, **not** a substitute for manufacturer documentation, and **not** suitable for a live freezer without professional review.

> **Never test on a production freezer or connected cold room.** Use a spare controller, lab bench, or disconnected unit only.

## Goal

Place a small Linux gateway **between the site router and the refrigeration controller** so that:

- The controller is **not** reachable from the public internet.
- Remote changes require an **operator token** (or equivalent staff channel).
- **Unsafe temperatures or defrost commands** are rejected and logged, with a human alert path (SMS, pager, on-call light — whatever the site already uses).

AegisGrid’s DuckDB CLI (`core.py` / `aegisgrid`) models token checks, bounds, and audit on the gateway itself. The [freezer hack simulation](../examples/freezer_hack_sim/) shows the same idea in toy HTTP form.

## Parts (generic)

- Raspberry Pi board in a simple case (no soldering required for a breadboard/lab setup).
- MicroSD card flashed with a minimal Linux image.
- USB Ethernet adapter **or** second NIC if the Pi model has one.
- Short Ethernet cables.
- USB power supply appropriate for the Pi.

Use only hardware you already own or can borrow for a **lab** setup. This document does not recommend vendors or SKUs.

## Logical wiring

```text
[Site router] ----ethernet----> [Pi gateway (AegisGrid / your policy)]
                                    |
                                    +----ethernet----> [Refrigeration controller LAN port]
```

The Pi terminates the **only** routed path from the shop LAN (or a dedicated VLAN) to the controller. Staff laptops reach the Pi; the controller’s management port does not get a public route.

## Software steps (high level)

1. Flash the SD card and complete first boot (SSH or local console).
2. Install Python 3.11+ and AegisGrid from this repository (`pip install -e .`).
3. Run `aegisgrid init` on the Pi; store the operator token offline for staff.
4. Configure the Pi firewall so **only** the gateway process (or reverse proxy in front of it) may forward to the controller’s IP on the private link.
5. Map real controller commands to your site’s protocol **only after** reading the manufacturer manual — this repo does not ship field drivers.

## Suggested safety checks (lab / spare controller)

| Check | Expect |
|-------|--------|
| Port scan from outside the shop network | Controller management IP **not** reachable |
| Wrong password / no token | Command **rejected**, event in audit log |
| Setpoint outside allowed freezer band (e.g. +50 °C) | **Blocked**, alert recorded (simulate SMS or local log) |
| Staff token, setpoint −18 °C (inside band) | **Allowed**, normal cooling continues |

Repeat after any change. If anything unexpected happens, power down the spare controller and disconnect the gateway.

## Relationship to the simulation

The [freezer hack simulation](../examples/freezer_hack_sim/) runs entirely on `127.0.0.1`. A Pi deployment would replace the toy HTTP controller with real hardware interfaces — which this repository does **not** include.

## Limits

- **Untested:** no step in this guide has been verified on a specific Pi revision or controller model in this repo.
- **Not safety-certified:** physical interlocks and statutory compliance remain your responsibility; see [DISCLAIMER.md](../DISCLAIMER.md).
- **Voluntary open source:** shared free under MIT for study and adaptation, not as a turnkey appliance.
