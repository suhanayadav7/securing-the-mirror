"""A small water-system digital twin: physical plant, sensors and AI controller.

The four layers of paper Section III map onto the simulation like this:

    Layer 1 (Physical)     Plant + Sensor: true chlorine / pressure, noisy signed readings
    Layer 2 (Network)      Packets in transit - where a man-in-the-middle can tamper
    Layer 3 (Integration)  gateway.Gateway - validation depends on governance maturity
    Layer 4 (Feedback)     Controller: acts on the readings the gateway lets through

One simulation step is one minute.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import random
from dataclasses import dataclass

# Safe operating bands for the *true* physical state.
CHLORINE_SAFE = (0.2, 4.0)    # mg/L - below: under-disinfection; above: EPA MRDL of 4 mg/L
PRESSURE_SAFE = (30.0, 95.0)  # psi  - below: backflow/contamination risk; above: pipe stress, water hammer

CHLORINE_SETPOINT = 1.0
PRESSURE_SETPOINT = 60.0
NOMINAL_CHLORINE_DEMAND = 0.5
NOMINAL_WATER_DEMAND = 12.0

DOSE_MAX = 20.0    # physical limit of the dosing pump, mg/L
PUMP_MAX = 100.0   # pump speed, %


@dataclass
class Packet:
    """A sensor reading as it travels over the network (Layer 2)."""
    quantity: str      # "chlorine" or "pressure"
    channel: str       # "A" primary, "B" independent redundant sensor
    value: float
    t: int
    seq: int
    sig: str = ""

    def payload(self) -> bytes:
        return f"{self.quantity}|{self.channel}|{self.value:.6f}|{self.t}|{self.seq}".encode()


@dataclass
class Command:
    """A control signal to an actuator."""
    actuator: str      # "dose" or "pump"
    value: float
    source: str        # "controller", "workstation" (internal), "internet"
    t: int
    sig: str = ""

    def payload(self) -> bytes:
        return f"{self.actuator}|{self.value:.6f}|{self.source}|{self.t}".encode()


def sign(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify(key: bytes, payload: bytes, sig: str) -> bool:
    return bool(sig) and hmac.compare_digest(sign(key, payload), sig)


class Plant:
    """True physical state. First-order dynamics towards each actuator's equilibrium."""

    def __init__(self) -> None:
        self.chlorine = CHLORINE_SETPOINT
        self.pressure = PRESSURE_SETPOINT
        self.dose = CHLORINE_SETPOINT + NOMINAL_CHLORINE_DEMAND
        self.pump = (PRESSURE_SETPOINT + NOMINAL_WATER_DEMAND) / 1.4
        self.chlorine_demand = NOMINAL_CHLORINE_DEMAND
        self.water_demand = NOMINAL_WATER_DEMAND

    def step(self, t: int, rng: random.Random, contamination: float = 0.0) -> None:
        self.chlorine_demand = (NOMINAL_CHLORINE_DEMAND + contamination
                                + 0.03 * math.sin(2 * math.pi * t / 180) + rng.gauss(0, 0.01))
        self.water_demand = NOMINAL_WATER_DEMAND + 3 * math.sin(2 * math.pi * t / 240) + rng.gauss(0, 0.3)
        self.chlorine = max(0.0, self.chlorine + 0.2 * ((self.dose - self.chlorine_demand) - self.chlorine))
        self.pressure = max(0.0, self.pressure + 0.3 * ((1.4 * self.pump - self.water_demand) - self.pressure))

    def apply(self, actuator: str, value: float) -> None:
        if actuator == "dose":
            self.dose = min(max(value, 0.0), DOSE_MAX)
        elif actuator == "pump":
            self.pump = min(max(value, 0.0), PUMP_MAX)


class Sensors:
    """Two independent sensors per quantity; each signs its own packets."""

    NOISE = {"chlorine": 0.02, "pressure": 0.5}

    def __init__(self, keys: dict[str, bytes]) -> None:
        self.keys = keys
        self.seq = 0

    def read(self, plant: Plant, t: int, rng: random.Random, physical_tamper=None) -> dict[tuple[str, str], Packet]:
        packets = {}
        for quantity, truth in (("chlorine", plant.chlorine), ("pressure", plant.pressure)):
            for channel in ("A", "B"):
                value = truth + rng.gauss(0, self.NOISE[quantity])
                if physical_tamper:
                    value = physical_tamper(quantity, channel, value, t)
                self.seq += 1
                pkt = Packet(quantity, channel, value, t, self.seq)
                pkt.sig = sign(self.keys[f"sensor-{channel}"], pkt.payload())
                packets[(quantity, channel)] = pkt
        return packets


class Controller:
    """The twin's AI decision layer: PI control of chlorine dosing and pump speed."""

    def __init__(self, key: bytes) -> None:
        self.key = key
        self.i_cl = 0.0
        self.i_p = 0.0

    def step(self, readings: dict[str, float], t: int) -> list[Command]:
        e_cl = CHLORINE_SETPOINT - readings["chlorine"]
        dose, self.i_cl = _pi(CHLORINE_SETPOINT + NOMINAL_CHLORINE_DEMAND, e_cl, self.i_cl, 1.0, 0.08, 10.0)

        e_p = PRESSURE_SETPOINT - readings["pressure"]
        pump, self.i_p = _pi((PRESSURE_SETPOINT + NOMINAL_WATER_DEMAND) / 1.4, e_p, self.i_p, 0.3, 0.04, PUMP_MAX)

        cmds = [
            Command("dose", dose, "controller", t),
            Command("pump", pump, "controller", t),
        ]
        for c in cmds:
            c.sig = sign(self.key, c.payload())
        return cmds


def _pi(bias: float, error: float, integral: float, kp: float, ki: float, hi: float) -> tuple[float, float]:
    """PI step with conditional-integration anti-windup; returns (output, new integral)."""
    raw = bias + kp * error + ki * (integral + error)
    if (raw > hi and error > 0) or (raw < 0 and error < 0):
        raw = bias + kp * error + ki * integral   # saturated: stop integrating
    else:
        integral += error
    return min(max(raw, 0.0), hi), integral


def predict(quantity: str, estimate: float, plant_inputs: dict[str, float]) -> float:
    """The twin's physics model: next value expected from the last trusted estimate."""
    if quantity == "chlorine":
        return estimate + 0.2 * ((plant_inputs["dose"] - NOMINAL_CHLORINE_DEMAND) - estimate)
    return estimate + 0.3 * ((1.4 * plant_inputs["pump"] - NOMINAL_WATER_DEMAND) - estimate)


def is_safe(quantity: str, value: float) -> bool:
    lo, hi = CHLORINE_SAFE if quantity == "chlorine" else PRESSURE_SAFE
    return lo <= value <= hi
