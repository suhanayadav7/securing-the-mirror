"""Risk-scoring framework and governance maturity scale (paper Section IV).

Each inter-departmental data handoff is scored 1-5 on four criteria:

    DFD  Data Freshness Dependency   how badly stale data degrades AI decisions
    VM   Validation Maturity         scored inversely: 5 = raw readings trusted as-is
    ADD  AI-Decision Dependency      5 = AI acts with no human confirmation
    CS   Consequence Severity        5 = risk to public health / threat to life

The composite risk is the arithmetic mean of the four.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Maturity(IntEnum):
    UNGOVERNED = 1
    MONITORED = 2
    VALIDATED = 3
    RESILIENT = 4

    @property
    def label(self) -> str:
        return f"Level {self.value} - {self.name.title()}"


MATURITY_INFO = {
    Maturity.UNGOVERNED: {
        "description": "No validation of incoming data; no named accountability if AI acts on bad input.",
        "technical": "Raw sensor stream trusted directly by AI; no validation middleware.",
    },
    Maturity.MONITORED: {
        "description": "Anomalies logged but no formal response mandated; accountability unclear.",
        "technical": "Logging/alerting in integration layer; no automated response, no response owner.",
    },
    Maturity.VALIDATED: {
        "description": "Data inputs formally validated; a named person reviews anomaly flags before the AI acts.",
        "technical": "Schema/range validation + anomaly detection at Layer 3; human-in-loop before control signal fires.",
    },
    Maturity.RESILIENT: {
        "description": "System detects tampering/anomalies autonomously and fails safely without human intervention.",
        "technical": "Cryptographic integrity checks, physics-based validation, automated rollback, full audit trail.",
    },
}

CRITERIA = {
    "dfd": ("Data Freshness Dependency", "1 = hours/days-old data is fine; 5 = seconds of delay cause wrong decisions"),
    "vm": ("Validation Maturity", "1 = formal schema/range + cross-sensor checks; 5 = raw readings trusted as-is"),
    "add": ("AI-Decision Dependency", "1 = human always reviews before action; 5 = AI acts fully automatically"),
    "cs": ("Consequence Severity", "1 = cost or minor delay; 5 = public-health risk, structural damage, threat to life"),
}

# Actions required to move a handoff *into* each level (Sections IV-C, VI, VIII-C).
TRANSITION_ACTIONS = {
    Maturity.MONITORED: [
        "Remove internet exposure of PLCs/HMIs and segment IT from OT networks",
        "Replace default and shared credentials; enforce authenticated command channels",
        "Log and alert on out-of-range readings and control commands in the integration layer",
    ],
    Maturity.VALIDATED: [
        "Enforce schema, range and rate-of-change validation before the AI ingests data",
        "Bound control commands to a safe operating envelope",
        "Name an accountable reviewer who approves flagged readings/commands before a control signal fires",
    ],
    Maturity.RESILIENT: [
        "Cryptographically sign sensor packets and controller commands (integrity + freshness)",
        "Physics-based cross-sensor validation using redundant, independent sensors",
        "Automatic fail-safe: reject tampered input, fail over to trusted data, roll back unsafe commands",
        "Keep a full audit trail of every AI-triggered intervention",
    ],
}


def _check_score(name: str, value: int) -> None:
    if not isinstance(value, int) or not 1 <= value <= 5:
        raise ValueError(f"{name} must be an integer from 1 to 5, got {value!r}")


@dataclass(frozen=True)
class Handoff:
    name: str
    dfd: int
    vm: int
    add: int
    cs: int
    maturity: Maturity = Maturity.UNGOVERNED
    note: str = ""

    def __post_init__(self) -> None:
        for key in CRITERIA:
            _check_score(key.upper(), getattr(self, key))
        object.__setattr__(self, "maturity", Maturity(self.maturity))

    @property
    def scores(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in CRITERIA}

    @property
    def composite(self) -> float:
        return (self.dfd + self.vm + self.add + self.cs) / 4

    @property
    def risk_band(self) -> str:
        c = self.composite
        if c >= 4.0:
            return "Critical"
        if c >= 3.0:
            return "High"
        if c >= 2.0:
            return "Moderate"
        return "Low"

    @property
    def required_maturity(self) -> Maturity:
        """Minimum maturity this handoff should operate at.

        Every handoff needs basic hygiene and monitoring (Level 2). High-risk or
        high-consequence handoffs need a human-in-loop check (Level 3). Autonomous
        AI control over safety-critical data needs autonomous fail-safes (Level 4) -
        the paper's rule: reach Level 3 *before* enabling autonomous control.
        """
        if self.add >= 4 and self.cs >= 4:
            return Maturity.RESILIENT
        if self.composite >= 3.0 or self.cs >= 4:
            return Maturity.VALIDATED
        return Maturity.MONITORED

    @property
    def gap(self) -> int:
        return max(0, self.required_maturity - self.maturity)

    def recommendations(self) -> list[str]:
        recs = []
        for level in Maturity:
            if self.maturity < level <= self.required_maturity:
                recs.extend(TRANSITION_ACTIONS[level])
        if self.required_maturity == Maturity.RESILIENT and self.maturity < Maturity.VALIDATED:
            recs.insert(0, "Until Level 3 is in place, require human confirmation before the AI "
                           "acts on this data (cap AI-Decision Dependency at 2)")
        return recs


@dataclass
class Assessment:
    handoffs: list[Handoff] = field(default_factory=list)

    def ranked(self) -> list[Handoff]:
        """Highest priority first: biggest governance gap, then highest composite risk."""
        return sorted(self.handoffs, key=lambda h: (h.gap, h.composite), reverse=True)

    def priority_gaps(self) -> list[Handoff]:
        return [h for h in self.ranked() if h.gap > 0]

    def mismatches(self) -> list[Handoff]:
        """The paper's 'critical mismatch': high-risk handoffs left at Level 1-2."""
        return [h for h in self.ranked() if h.composite >= 3.5 and h.maturity <= Maturity.MONITORED]

    def to_rows(self) -> list[dict]:
        return [
            {
                "handoff": h.name,
                "DFD": h.dfd,
                "VM": h.vm,
                "ADD": h.add,
                "CS": h.cs,
                "composite": round(h.composite, 2),
                "band": h.risk_band,
                "current": int(h.maturity),
                "required": int(h.required_maturity),
                "gap": h.gap,
            }
            for h in self.ranked()
        ]
