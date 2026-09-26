"""Run an attack scenario against the twin at a given governance maturity level."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .attacks import make
from .framework import Maturity
from .gateway import Gateway, GatewayConfig
from .twin import Controller, Plant, Sensors, is_safe


@dataclass
class SimConfig:
    duration: int = 360       # minutes
    attack_start: int = 60
    seed: int = 7
    gateway: GatewayConfig = field(default_factory=GatewayConfig)


@dataclass
class Result:
    scenario: str
    level: Maturity
    detected_after: int | None      # minutes from attack start to first alert
    contained_after: int | None     # minutes from attack start to containment
    unsafe_minutes: int             # minutes the true state was outside the safe band
    peak_chlorine: float
    min_chlorine: float
    peak_pressure: float
    min_pressure: float
    false_alarms: int               # alerts raised before the attack began
    alerts: list[tuple[int, str]]
    trace: list[dict]

    @property
    def outcome(self) -> str:
        if self.unsafe_minutes == 0:
            return "Safe"
        if self.contained_after is not None and self.unsafe_minutes <= 15:
            return "Near miss"
        return "Harm"

    def summary(self) -> dict:
        return {
            "scenario": self.scenario,
            "level": int(self.level),
            "outcome": self.outcome,
            "detected_after_min": self.detected_after,
            "contained_after_min": self.contained_after,
            "unsafe_min": self.unsafe_minutes,
            "peak_chlorine": round(self.peak_chlorine, 2),
            "min_chlorine": round(self.min_chlorine, 2),
            "peak_pressure": round(self.peak_pressure, 1),
            "min_pressure": round(self.min_pressure, 1),
            "false_alarms": self.false_alarms,
        }


def run(scenario: str, level: Maturity | int, cfg: SimConfig | None = None) -> Result:
    cfg = cfg or SimConfig()
    level = Maturity(level)
    rng = random.Random(cfg.seed)
    keys = {name: rng.randbytes(32) for name in ("sensor-A", "sensor-B", "controller")}

    attack = make(scenario)
    plant = Plant()
    sensors = Sensors(keys)
    controller = Controller(keys["controller"])
    gateway = Gateway(level, keys, cfg.gateway, rng=random.Random(f"humans-{cfg.seed}-{int(level)}"))

    trace: list[dict] = []
    unsafe = 0
    start = cfg.attack_start
    for t in range(cfg.duration):
        gateway.tick(t)
        active = t >= start and not gateway.contained

        tamper = (lambda q, c, v, tt: attack.physical_tamper(q, c, v, tt, start)) if active else None
        packets = sensors.read(plant, t, rng, tamper)             # Layer 1
        if active:
            attack.tamper_packets(packets, t)                     # Layer 2
        readings = gateway.ingest(packets, t, plant)              # Layer 3
        commands = controller.step(readings, t)                   # Layer 4
        if active:
            commands += attack.inject_commands(t)
        for actuator, value in gateway.authorize(commands, t).items():
            plant.apply(actuator, value)

        plant.step(t, rng, attack.contamination if t >= start else 0.0)

        safe = is_safe("chlorine", plant.chlorine) and is_safe("pressure", plant.pressure)
        unsafe += not safe
        trace.append({
            "t": t,
            "chlorine_true": plant.chlorine,
            "chlorine_seen": readings["chlorine"],
            "pressure_true": plant.pressure,
            "pressure_seen": readings["pressure"],
            "dose": plant.dose,
            "pump": plant.pump,
            "safe": safe,
        })

    def since_start(x: int | None) -> int | None:
        return None if x is None or x < start else x - start

    return Result(
        scenario=scenario,
        level=level,
        detected_after=since_start(gateway.first_detect),
        contained_after=since_start(gateway.contained_at),
        unsafe_minutes=unsafe,
        peak_chlorine=max(r["chlorine_true"] for r in trace),
        min_chlorine=min(r["chlorine_true"] for r in trace),
        peak_pressure=max(r["pressure_true"] for r in trace),
        min_pressure=min(r["pressure_true"] for r in trace),
        false_alarms=sum(1 for ts, _ in gateway.alerts if ts < start),
        alerts=gateway.alerts,
        trace=trace,
    )


def monte_carlo(scenario: str, level: Maturity | int, cfg: SimConfig | None = None, runs: int = 200) -> dict:
    """Repeat a scenario over many seeds (sensor noise and human behaviour) and summarise."""
    cfg = cfg or SimConfig()
    results = [run(scenario, level, SimConfig(cfg.duration, cfg.attack_start, cfg.seed + i, cfg.gateway))
               for i in range(runs)]
    outcomes = [r.outcome for r in results]
    unsafe = sorted(r.unsafe_minutes for r in results)
    contained = sorted(r.contained_after for r in results if r.contained_after is not None)
    return {
        "scenario": scenario,
        "level": int(Maturity(level)),
        "runs": runs,
        "p_safe": round(outcomes.count("Safe") / runs, 3),
        "p_near_miss": round(outcomes.count("Near miss") / runs, 3),
        "p_harm": round(outcomes.count("Harm") / runs, 3),
        "median_unsafe_min": unsafe[runs // 2],
        "p90_unsafe_min": unsafe[int(runs * 0.9) - 1],
        "median_contained_min": contained[len(contained) // 2] if contained else None,
        "p_contained": round(len(contained) / runs, 3),
    }


def matrix(scenarios: list[str], cfg: SimConfig | None = None) -> list[Result]:
    return [run(s, level, cfg) for s in scenarios for level in Maturity]
