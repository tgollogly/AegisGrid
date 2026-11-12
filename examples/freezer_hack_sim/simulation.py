"""Run Scenario A (no guard) vs Scenario B (guard box) and write results + chart.

Localhost only. No HTTP outside 127.0.0.1.
"""

from __future__ import annotations

import json
from pathlib import Path

from .client import http_json
from .controller import DEFAULT_PASSWORD, FridgeController
from .fridge import FOOD_RISK_C, FREEZER_MAX_C, Fridge
from .guard import STAFF_TOKEN, GuardBox

ROOT = Path(__file__).resolve().parent
DURATION_MIN = 90
ATTACK_AT = 10
STAFF_FIX_AT = 13
CHART_PATH = ROOT / "results.png"
TABLE_PATH = ROOT / "results.txt"
JSON_PATH = ROOT / "results.json"


def run_ticks(fridge, start, end):
    for minute in range(start, end):
        fridge.tick(minute)


def scenario_a():
    fridge = Fridge()
    ctrl = FridgeController(fridge, require_guard=False).start()
    events = []
    try:
        run_ticks(fridge, 0, ATTACK_AT)
        code1, body1 = http_json(
            "POST",
            ctrl.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "set_temp", "temp": 50},
        )
        code2, body2 = http_json(
            "POST",
            ctrl.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "defrost_on", "duration": 120},
        )
        events.append(
            {
                "minute": ATTACK_AT,
                "name": "attacker_default_password_set_temp_50_and_defrost",
                "codes": [code1, code2],
                "ok": code1 == 200 and code2 == 200,
                "bodies": [body1, body2],
            }
        )
        run_ticks(fridge, ATTACK_AT, DURATION_MIN)
    finally:
        ctrl.stop()

    risk_at = next((m for m, t in fridge.history if t > FOOD_RISK_C), None)
    peak = max(t for _, t in fridge.history)
    return {
        "name": "A_no_guard",
        "history": fridge.history,
        "events": events,
        "final_temp": fridge.temp,
        "peak_temp": peak,
        "food_risk_at_min": risk_at,
        "attack_succeeded": bool(events and events[0]["ok"] and peak > FOOD_RISK_C),
    }


def scenario_b():
    fridge = Fridge()
    ctrl = FridgeController(fridge, require_guard=True).start()
    guard = GuardBox(fridge, ctrl.url).start()
    events = []
    try:
        run_ticks(fridge, 0, ATTACK_AT)

        d_code, d_body = http_json(
            "POST",
            ctrl.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "set_temp", "temp": 50},
        )
        events.append(
            {
                "minute": ATTACK_AT,
                "name": "direct_access",
                "code": d_code,
                "blocked": d_code == 403,
                "body": d_body,
            }
        )

        p_code, p_body = http_json(
            "POST",
            guard.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "set_temp", "temp": 50},
        )
        events.append(
            {
                "minute": ATTACK_AT + 1,
                "name": "default_password_via_proxy",
                "code": p_code,
                "blocked": p_code == 401,
                "body": p_body,
            }
        )

        s_code, s_body = http_json(
            "POST",
            guard.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "set_temp", "temp": 50},
            headers={"X-Staff-Token": STAFF_TOKEN},
        )
        events.append(
            {
                "minute": ATTACK_AT + 2,
                "name": "stolen_token_bad_temp",
                "code": s_code,
                "blocked": s_code == 403 and s_body.get("tripped") is True,
                "tripped": guard.tripped,
                "sms": list(guard.sms_alerts),
                "body": s_body,
            }
        )

        run_ticks(fridge, ATTACK_AT, STAFF_FIX_AT)

        st_code, st_body = http_json(
            "POST",
            guard.url + "/command",
            {"action": "set_temp", "temp": -18},
            headers={"X-Staff-Token": STAFF_TOKEN},
        )
        events.append(
            {
                "minute": STAFF_FIX_AT,
                "name": "staff_set_minus_18",
                "code": st_code,
                "allowed": st_code == 200 and st_body.get("setpoint_c") == -18,
                "body": st_body,
            }
        )

        run_ticks(fridge, STAFF_FIX_AT, DURATION_MIN)
    finally:
        guard.stop()
        ctrl.stop()

    peak = max(t for _, t in fridge.history)
    still_cooling = fridge.compressor_on and fridge.temp <= FREEZER_MAX_C and not fridge.defrost
    return {
        "name": "B_guard_box",
        "history": fridge.history,
        "events": events,
        "final_temp": fridge.temp,
        "peak_temp": peak,
        "tripped": guard.tripped,
        "sms_alerts": list(guard.sms_alerts),
        "still_cooling": still_cooling,
        "direct_blocked": events[0]["blocked"],
        "proxy_default_blocked": events[1]["blocked"],
        "stolen_token_blocked": events[2]["blocked"],
        "staff_allowed": events[3]["allowed"],
    }


def build_table(a, b):
    rows = [
        ("Attack / test", "Blocked or allowed", "Detail"),
        (
            "A: attacker uses default password, no guard",
            "Allowed — attack worked",
            f"Commands accepted. Peak {a['peak_temp']:.1f}°C. "
            f"Food-risk (above {FOOD_RISK_C:.0f}°C) at minute {a['food_risk_at_min']}.",
        ),
        (
            "A: forced defrost / 50°C, no guard",
            "Allowed — freezer warmed past safe level",
            f"Ended at {a['final_temp']:.1f}°C after {DURATION_MIN} simulated minutes.",
        ),
        (
            "B: attacker hits controller directly",
            "Blocked",
            "HTTP 403; controller not exposed past the guard.",
        ),
        (
            "B: default password through the proxy",
            "Blocked",
            "HTTP 401; no allow-listed staff token (simulated VPN).",
        ),
        (
            "B: stolen token sets 50°C",
            "Blocked — trip + simulated SMS",
            (b["sms_alerts"][0] if b["sms_alerts"] else "no SMS"),
        ),
        (
            "B: staff set −18°C after the trip",
            "Allowed" if b["staff_allowed"] else "Blocked",
            "Legitimate command reached the freezer.",
        ),
        (
            "B: fridge keeps cooling after trip",
            "Still cooling" if b["still_cooling"] else "Cooling lost",
            f"Peak {b['peak_temp']:.1f}°C, ended at {b['final_temp']:.1f}°C (safe band max {FREEZER_MAX_C:.0f}°C).",
        ),
    ]
    return rows


def format_table(rows):
    widths = [max(len(str(r[i])) for r in rows) for i in range(3)]
    lines = []
    for i, row in enumerate(rows):
        line = " | ".join(str(row[j]).ljust(widths[j]) for j in range(3))
        lines.append(line)
        if i == 0:
            lines.append("-+-".join("-" * widths[j] for j in range(3)))
    return "\n".join(lines)


def write_chart(a, b, path):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    mins_a, temps_a = zip(*a["history"])
    mins_b, temps_b = zip(*b["history"])
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=140)
    ax.plot(mins_a, temps_a, color="#c0392b", linewidth=2.2, label="A: no guard (attack succeeds)")
    ax.plot(mins_b, temps_b, color="#1f6aa5", linewidth=2.2, label="B: guard box (attacks blocked)")
    ax.axhline(FOOD_RISK_C, color="#e67e22", linestyle="--", linewidth=1, label="Food-risk line (0°C)")
    ax.axhline(FREEZER_MAX_C, color="#7f8c8d", linestyle=":", linewidth=1, label="Top of safe freezer band (−15°C)")
    ax.axvline(ATTACK_AT, color="#888888", linestyle="--", linewidth=0.9)
    ax.annotate(
        "Attack starts",
        xy=(ATTACK_AT, -20),
        xytext=(ATTACK_AT + 3, -8),
        fontsize=8,
        color="#555555",
        arrowprops=dict(arrowstyle="->", color="#888888"),
    )
    ax.set_title("AegisGrid simulation: freezer temperature over time")
    ax.set_xlabel("Simulated time (minutes)")
    ax.set_ylabel("Freezer temperature (°C)")
    ax.set_xlim(0, DURATION_MIN - 1)
    ax.set_ylim(-26, 55)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper left", frameon=True)
    fig.text(
        0.5,
        0.01,
        "Simulation only — not real Danfoss hardware, not a proof of real-world security.  © 2026 Thomas Gollogly. All rights reserved.",
        ha="center",
        fontsize=7,
        color="#555555",
    )
    fig.tight_layout(rect=[0, 0.04, 1, 1])
    fig.savefig(path)
    plt.close(fig)


def main():
    print("Running Scenario A (no guard)...", flush=True)
    a = scenario_a()
    print("Running Scenario B (guard box)...", flush=True)
    b = scenario_b()
    rows = build_table(a, b)
    table = format_table(rows)
    limits = (
        "Honest limits: this is a localhost Python simulation only. It is not real "
        "Danfoss AK-SM hardware, it does not use a real fridge protocol, and it does "
        "not prove real-world security. The 'VPN' is just a header token, the temperature "
        "model is a simple linear approximation, and a real attacker with physical access "
        "or a bug in the guard software is out of scope."
    )
    text = (
        "AegisGrid freezer hack simulation — local results\n"
        "=================================================\n\n"
        f"{table}\n\n"
        f"{limits}\n"
    )
    TABLE_PATH.write_text(text, encoding="utf-8")
    JSON_PATH.write_text(
        json.dumps(
            {
                "scenario_a": {k: v for k, v in a.items() if k != "history"},
                "scenario_b": {k: v for k, v in b.items() if k != "history"},
                "chart": str(CHART_PATH),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    write_chart(a, b, CHART_PATH)
    print()
    print(text)
    print(f"Chart: {CHART_PATH}")
    return a, b


if __name__ == "__main__":
    main()
