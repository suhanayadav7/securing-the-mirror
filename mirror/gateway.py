"""Layer 3 integration gateway. What it checks depends on governance maturity (Table I).

    Level 1 Ungoverned  readings and commands pass straight through
    Level 2 Monitored   authenticated command channel (no internet exposure / default creds);
                        anomalies are logged, and an operator responds after a delay
    Level 3 Validated   schema/range/rate-of-change checks and a command envelope; flagged
                        items are held for a named reviewer who verifies against a field sample
    Level 4 Resilient   signed packets and commands, redundant-sensor cross-checks against the
                        twin's physics model, automatic fail-over and command rejection
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .framework import Maturity
from .twin import Command, Packet, Plant, predict, verify

# Plausibility limits used by the Level 2/3 detectors.
RANGE = {"chlorine": (0.2, 4.0), "pressure": (30.0, 95.0)}
MAX_RATE = {"chlorine": 0.3, "pressure": 8.0}           # max change per minute
CROSS_TOLERANCE = {"chlorine": 0.25, "pressure": 5.0}   # A vs B disagreement
ENVELOPE = {"dose": (0.0, 5.0), "pump": (0.0, 90.0)}    # safe command envelope
REVIEW_TOLERANCE = {"chlorine": 0.3, "pressure": 6.0}   # reviewer vs field sample


@dataclass
class GatewayConfig:
    """How the humans in the loop behave.

    The defaults are an *ideal* human: fixed response times, never wrong. `realistic()` draws
    response times from a right-skewed (lognormal) distribution around the same medians and lets
    the Level 3 reviewer wrongly approve a flagged item - alert fatigue, a bad field sample, or
    trusting the screen.
    """
    operator_delay: int = 45            # Level 2: median minutes before someone acts on a logged alert
    review_delay: int = 10              # Level 3: median minutes for the named reviewer to verify a flag
    reviewer_miss_rate: float = 0.0     # Level 3: chance a review wrongly approves a bad item
    jitter: bool = False                # draw response times instead of using the medians

    @classmethod
    def realistic(cls, operator_delay: int = 45, review_delay: int = 10, reviewer_miss_rate: float = 0.1):
        return cls(operator_delay, review_delay, reviewer_miss_rate, jitter=True)


@dataclass
class Gateway:
    level: Maturity
    keys: dict[str, bytes]
    cfg: GatewayConfig = field(default_factory=GatewayConfig)
    trusted: dict[str, float] = field(default_factory=lambda: {"chlorine": 1.0, "pressure": 60.0})
    applied: dict[str, float] = field(default_factory=dict)
    alerts: list[tuple[int, str]] = field(default_factory=list)
    first_detect: int | None = None
    contained_at: int | None = None
    _pending_review: int | None = None
    _flag_is_bad: bool = False
    _approved_at: int | None = None
    rng: random.Random = field(default_factory=random.Random)
    _operator_delay: int | None = None

    def _delay(self, median: int, sigma: float) -> int:
        if not self.cfg.jitter:
            return median
        return max(1, round(median * self.rng.lognormvariate(0, sigma)))

    @property
    def contained(self) -> bool:
        return self.contained_at is not None

    def _alert(self, t: int, msg: str) -> None:
        if self.first_detect is None:
            self.first_detect = t
        self.alerts.append((t, msg))

    def _contain(self, t: int, msg: str) -> None:
        if self.contained_at is None:
            self.contained_at = t
            self.alerts.append((t, "CONTAINED: " + msg))

    def _suspicious(self, quantity: str, value: float) -> str | None:
        lo, hi = RANGE[quantity]
        if not lo <= value <= hi:
            return f"{quantity} reading {value:.2f} outside plausible range {lo}-{hi}"
        if abs(value - self.trusted[quantity]) > MAX_RATE[quantity]:
            return f"{quantity} changed {value - self.trusted[quantity]:+.2f} in one minute"
        return None

    def _queue_review(self, t: int, is_bad: bool) -> None:
        if self._pending_review is None:
            self._pending_review = t + self._delay(self.cfg.review_delay, 0.6)
        self._flag_is_bad = self._flag_is_bad or is_bad

    def tick(self, t: int) -> None:
        """Humans in the loop act at the start of each minute."""
        if self.level == Maturity.MONITORED and self.first_detect is not None:
            if self._operator_delay is None:
                self._operator_delay = self._delay(self.cfg.operator_delay, 0.8)
            if t >= self.first_detect + self._operator_delay:
                self._contain(t, "operator responded to logged alert, isolated channel")
        if self.level == Maturity.VALIDATED and self._pending_review is not None and t >= self._pending_review:
            if self._flag_is_bad and self.rng.random() >= self.cfg.reviewer_miss_rate:
                self._contain(t, "reviewer rejected flagged input after field verification, isolated channel")
            else:
                if self._flag_is_bad:
                    self.alerts.append((t, "REVIEWER MISS: flagged input approved in error"))
                self._approved_at = t  # reviewer releases the current reading/command
            self._pending_review = None
            self._flag_is_bad = False

    # ---- sensor data --------------------------------------------------------------------------

    def ingest(self, packets: dict[tuple[str, str], Packet], t: int, plant: Plant) -> dict[str, float]:
        readings = {}
        for quantity in ("chlorine", "pressure"):
            a, b = packets[(quantity, "A")], packets[(quantity, "B")]
            truth = getattr(plant, quantity)
            if self.level == Maturity.RESILIENT:
                value = self._ingest_resilient(quantity, a, b, t, plant)
            else:
                value = a.value
                problem = self._suspicious(quantity, value) if self.level >= Maturity.MONITORED else None
                if problem and self._approved_at == t:
                    problem = None
                if problem:
                    self._alert(t, problem)
                    if self.level == Maturity.VALIDATED:
                        # hold the last trusted value; the reviewer later compares the
                        # flagged reading with a field sample (the true value)
                        self._queue_review(t, abs(value - truth) > REVIEW_TOLERANCE[quantity])
                        value = self.trusted[quantity]
            self.trusted[quantity] = value
            readings[quantity] = value
        return readings

    def _ingest_resilient(self, quantity: str, a: Packet, b: Packet, t: int, plant: Plant) -> float:
        valid = []
        for pkt in (a, b):
            if not verify(self.keys[f"sensor-{pkt.channel}"], pkt.payload(), pkt.sig):
                self._alert(t, f"{quantity}/{pkt.channel}: integrity check failed (tampered or forged packet)")
            elif pkt.t != t:
                self._alert(t, f"{quantity}/{pkt.channel}: stale packet (replay)")
            else:
                valid.append(pkt)

        if len(valid) == 2 and abs(a.value - b.value) > CROSS_TOLERANCE[quantity]:
            expected = predict(quantity, self.trusted[quantity], {"dose": plant.dose, "pump": plant.pump})
            keep = min(valid, key=lambda p: abs(p.value - expected))
            drop = b if keep is a else a
            self._alert(t, f"{quantity}: sensor {drop.channel} disagrees with sensor {keep.channel} and the "
                           f"physics model ({drop.value:.2f} vs expected {expected:.2f}) - failed over")
            valid = [keep]

        if not valid:
            self._alert(t, f"{quantity}: no trustworthy reading - holding last known good value")
            return self.trusted[quantity]
        if len(valid) < 2:
            self._contain(t, f"automatic fail-over for {quantity}")
        return sum(p.value for p in valid) / len(valid) if len(valid) == 2 else valid[0].value

    # ---- control commands ---------------------------------------------------------------------

    def authorize(self, commands: list[Command], t: int) -> dict[str, float]:
        """Return the actuator settings that are allowed to reach the plant this minute."""
        out: dict[str, float] = {}
        for cmd in commands:
            lo, hi = ENVELOPE[cmd.actuator]
            outside = not lo <= cmd.value <= hi

            if self.level >= Maturity.MONITORED and cmd.source == "internet":
                self._alert(t, f"blocked unauthenticated {cmd.actuator} command from the internet")
                self._contain(t, "internet-exposed control path closed")
                continue

            if self.level == Maturity.RESILIENT:
                if not verify(self.keys["controller"], cmd.payload(), cmd.sig):
                    self._alert(t, f"rejected unsigned {cmd.actuator} command from {cmd.source} "
                                   f"({cmd.value:.1f})")
                    self._contain(t, "unauthorised command rejected automatically")
                    continue
                if outside:
                    self._alert(t, f"{cmd.actuator} command {cmd.value:.1f} clamped to safe envelope")
                    cmd = Command(cmd.actuator, min(max(cmd.value, lo), hi), cmd.source, t)
                out[cmd.actuator] = cmd.value

            elif self.level == Maturity.VALIDATED:
                if (outside or cmd.source != "controller") and self._approved_at != t:
                    self._alert(t, f"{cmd.actuator} command {cmd.value:.1f} from {cmd.source} held for review")
                    self._queue_review(t, is_bad=outside or cmd.source != "controller")
                    continue
                out[cmd.actuator] = cmd.value

            else:
                if self.level == Maturity.MONITORED and outside:
                    self._alert(t, f"{cmd.actuator} command {cmd.value:.1f} outside envelope (logged only)")
                out[cmd.actuator] = cmd.value
        self.applied.update(out)
        return out
