"""Simple freezer temperature model. One tick = one simulated minute."""

AMBIENT_C = 20.0
HEATER_TARGET_C = 50.0  # what the 2026 attacks set controllers toward
COOL_RATE_C_PER_MIN = 0.8
DEFROST_HEAT_RATE_C_PER_MIN = 2.0
IDLE_WARM_RATE_C_PER_MIN = 0.25
DEFAULT_SETPOINT_C = -20.0
# Freezer band enforced by the guard (same pattern as AegisGrid temperature bounds).
FREEZER_MIN_C = -25.0
FREEZER_MAX_C = -15.0
# Frozen food is at short-term risk once it crosses thawing point.
FOOD_RISK_C = 0.0


class Fridge:
    def __init__(self, start_temp=DEFAULT_SETPOINT_C, setpoint=DEFAULT_SETPOINT_C):
        self.temp = float(start_temp)
        self.setpoint = float(setpoint)
        self.defrost = False
        self.defrost_remaining = 0
        self.compressor_on = True
        self.history = []  # (minute, temp_c)

    def tick(self, minute):
        if self.defrost:
            self.temp = min(HEATER_TARGET_C, self.temp + DEFROST_HEAT_RATE_C_PER_MIN)
            self.defrost_remaining -= 1
            if self.defrost_remaining <= 0:
                self.defrost = False
        elif self.compressor_on:
            if self.temp > self.setpoint:
                self.temp = max(self.setpoint, self.temp - COOL_RATE_C_PER_MIN)
            elif self.temp < self.setpoint:
                self.temp = min(self.setpoint, self.temp + 0.2)
        else:
            if self.temp < AMBIENT_C:
                self.temp = min(AMBIENT_C, self.temp + IDLE_WARM_RATE_C_PER_MIN)
        self.temp = round(self.temp, 3)
        self.history.append((int(minute), self.temp))

    def set_temp(self, temp_c):
        self.setpoint = float(temp_c)
        self.defrost = False
        self.defrost_remaining = 0

    def defrost_on(self, duration_min):
        duration_min = int(duration_min)
        if duration_min <= 0:
            raise ValueError("duration must be positive")
        self.defrost = True
        self.defrost_remaining = duration_min

    def cancel_defrost_keep_cooling(self):
        """After a trip, the freezer itself keeps cooling at the last safe setpoint."""
        self.defrost = False
        self.defrost_remaining = 0
        self.compressor_on = True
        if self.setpoint > FREEZER_MAX_C or self.setpoint < FREEZER_MIN_C:
            self.setpoint = DEFAULT_SETPOINT_C

    def status(self):
        return {
            "temp_c": self.temp,
            "setpoint_c": self.setpoint,
            "defrost": self.defrost,
            "defrost_remaining_min": self.defrost_remaining,
            "compressor_on": self.compressor_on,
        }
