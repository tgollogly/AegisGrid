# Why AegisGrid exists

AegisGrid was created **voluntarily** by [tgollogly](https://github.com/tgollogly) and released **free under the MIT Licence**. There is **no paid product**, **no subscription**, and **no income** from this repository.

## The problem

Food safety and personal resilience both depend on **cold storage working correctly**. Shops, community kitchens, labs, and connected **refrigeration gateways** are part of everyday life — and they are increasingly **network-connected**. When monitoring fails because of misconfiguration, tampering, or **cyber incidents** affecting operational or IoT kit, **temperature drift and spoilage** hurt small operators and households alike, not only large retailers.

**Enterprise security platforms are expensive.** Basic patterns — access control, audit trails, bounds checking, and software integrity — should not be locked behind price tags only big chains can afford.

## What AegisGrid is

A **reference implementation** (Python + DuckDB) for **local**, **offline-first** gateway policy:

- Hashed operator tokens and audit logging  
- A software model of temperature safety bounds (1°C–8°C) with watchdog behaviour  
- Local threat-indicator cache  
- Signed manifest verification, rollback, and network lockdown on detected tamper  

It includes automated **pytest** coverage and a CLI (`aegisgrid`). It is **not** cloud AI and does **not** require external services to run.

## What AegisGrid is not

- **Not** certified safety or food-hygiene equipment  
- **Not** a guarantee that attackers cannot compromise your systems  
- **Not** legal, regulatory, or food-safety advice  
- **Not** a replacement for physical thermal interlocks and professional engineering sign-off  

See [DISCLAIMER.md](DISCLAIMER.md).

## Who it is for

Anyone who wants **testable building blocks** to learn from or adapt on **small refrigeration / IoT gateways** — especially teams and individuals who need **defensive**, **local** tooling without enterprise budgets.

**Goal:** help communities **defend what they rely on** with honest, reviewable code — and invite improvements via open source.

## How to use this document

- **Install & run:** [QUICKSTART.md](QUICKSTART.md)  
- **Full reference:** [README.md](README.md)  
- **Licence:** [LICENSE](LICENSE)  

---

Copyright (c) 2026 tgollogly. SPDX-License-Identifier: MIT.
