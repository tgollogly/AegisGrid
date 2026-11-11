"""Pytest coverage for the localhost freezer hack simulation."""

from examples.freezer_hack_sim.client import http_json
from examples.freezer_hack_sim.controller import DEFAULT_PASSWORD, FridgeController
from examples.freezer_hack_sim.fridge import FOOD_RISK_C, FREEZER_MAX_C, Fridge
from examples.freezer_hack_sim.guard import STAFF_TOKEN, GuardBox
from examples.freezer_hack_sim.simulation import scenario_a, scenario_b


def _start_pair(require_guard=True):
    fridge = Fridge()
    ctrl = FridgeController(fridge, require_guard=require_guard).start()
    guard = GuardBox(fridge, ctrl.url).start() if require_guard else None
    return fridge, ctrl, guard


def _stop(ctrl, guard=None):
    if guard is not None:
        guard.stop()
    ctrl.stop()


def test_scenario_a_attack_succeeds_and_food_is_at_risk():
    a = scenario_a()
    assert a["attack_succeeded"] is True
    assert a["peak_temp"] > FOOD_RISK_C
    assert a["food_risk_at_min"] is not None
    assert a["final_temp"] > 20


def test_scenario_b_blocks_all_three_attacks():
    b = scenario_b()
    assert b["direct_blocked"] is True
    assert b["proxy_default_blocked"] is True
    assert b["stolen_token_blocked"] is True
    assert b["tripped"] is True
    assert b["sms_alerts"], "expected a simulated SMS alert"


def test_staff_can_still_operate_and_fridge_keeps_cooling():
    b = scenario_b()
    assert b["staff_allowed"] is True
    assert b["still_cooling"] is True
    assert b["final_temp"] <= FREEZER_MAX_C
    assert b["peak_temp"] <= FREEZER_MAX_C


def test_direct_access_blocked_when_guard_required():
    fridge, ctrl, guard = _start_pair(require_guard=True)
    try:
        code, body = http_json(
            "POST",
            ctrl.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "set_temp", "temp": 50},
        )
        assert code == 403
        assert fridge.setpoint == -20
        assert "not exposed" in body.get("reason", "")
    finally:
        _stop(ctrl, guard)


def test_default_password_via_proxy_blocked():
    fridge, ctrl, guard = _start_pair()
    try:
        code, body = http_json(
            "POST",
            guard.url + "/command",
            {"password": DEFAULT_PASSWORD, "action": "defrost_on", "duration": 120},
        )
        assert code == 401
        assert fridge.defrost is False
        assert "staff token" in body.get("reason", "")
    finally:
        _stop(ctrl, guard)


def test_stolen_token_unsafe_temp_trips_and_sends_sms():
    fridge, ctrl, guard = _start_pair()
    try:
        code, body = http_json(
            "POST",
            guard.url + "/command",
            {"action": "set_temp", "temp": 50},
            headers={"X-Staff-Token": STAFF_TOKEN},
        )
        assert code == 403
        assert body.get("tripped") is True
        assert guard.tripped is True
        assert fridge.setpoint != 50
        assert any("SMS ALERT" in s for s in guard.sms_alerts)
        assert fridge.compressor_on is True
        assert fridge.defrost is False
    finally:
        _stop(ctrl, guard)


def test_stolen_token_long_defrost_trips():
    fridge, ctrl, guard = _start_pair()
    try:
        code, body = http_json(
            "POST",
            guard.url + "/command",
            {"action": "defrost_on", "duration": 120},
            headers={"X-Staff-Token": STAFF_TOKEN},
        )
        assert code == 403
        assert body.get("tripped") is True
        assert fridge.defrost is False
        assert fridge.compressor_on is True
    finally:
        _stop(ctrl, guard)


def test_staff_legit_setpoint_allowed():
    fridge, ctrl, guard = _start_pair()
    try:
        code, body = http_json(
            "POST",
            guard.url + "/command",
            {"action": "set_temp", "temp": -18},
            headers={"X-Staff-Token": STAFF_TOKEN},
        )
        assert code == 200
        assert body.get("setpoint_c") == -18
        assert fridge.setpoint == -18
        assert guard.tripped is False
    finally:
        _stop(ctrl, guard)


def test_client_refuses_non_localhost():
    try:
        http_json("GET", "http://example.com/status")
        assert False, "should have refused"
    except ValueError as exc:
        assert "non-localhost" in str(exc)
