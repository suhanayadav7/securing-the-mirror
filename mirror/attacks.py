"""Attack scenarios, each tied to a failure mode or incident discussed in the paper."""

from __future__ import annotations

from dataclasses import dataclass

from .twin import Command, Packet


@dataclass
class Attack:
    key: str
    title: str
    layer: str
    paper_ref: str
    description: str

    contamination: float = 0.0   # extra chlorine demand while active (a real event the attacker hides)

    def physical_tamper(self, quantity: str, channel: str, value: float, t: int, start: int) -> float:
        return value

    def tamper_packets(self, packets: dict[tuple[str, str], Packet], t: int) -> None:
        pass

    def inject_commands(self, t: int) -> list[Command]:
        return []


class Baseline(Attack):
    def __init__(self) -> None:
        super().__init__("baseline", "No attack (baseline)", "-", "-",
                         "Normal operation. Used to check that no level raises false alarms.")


class ChlorineFDI(Attack):
    def __init__(self) -> None:
        super().__init__(
            "chlorine_fdi", "False low-chlorine injection", "Layer 2 (MITM on plaintext MQTT)",
            "Sec. III-A Layer 4; Israel 2020 (Sec. VI-B)",
            "Attacker rewrites the primary chlorine reading to 0.1 mg/L. The AI 'corrects' the phantom "
            "shortfall by raising dosing, overdosing the real water.")

    def tamper_packets(self, packets, t):
        packets[("chlorine", "A")].value = 0.1


class PressureFDI(Attack):
    def __init__(self) -> None:
        super().__init__(
            "pressure_fdi", "False low-pressure injection", "Layer 2 (MITM on plaintext MQTT)",
            "Sec. III-A Layer 4",
            "Attacker spoofs the primary pressure reading at 22 psi. The AI spins the pump up, driving real "
            "pressure into the water-hammer zone.")

    def tamper_packets(self, packets, t):
        packets[("pressure", "A")].value = 22.0


class DosingSetpointTamper(Attack):
    def __init__(self) -> None:
        super().__init__(
            "dosing_setpoint_tamper", "Dosing setpoint tampering (100x)", "Layer 4 (compromised workstation)",
            "Oldsmar 2021 (Sec. VI-C); Kemuri 2016 (Sec. VI-A)",
            "From a compromised operator workstation the attacker writes a dosing setpoint 100x normal "
            "(1.5 -> 150 mg/L); the pump saturates at its physical maximum.")

    def inject_commands(self, t):
        return [Command("dose", 150.0, "workstation", t)]


class PLCTakeover(Attack):
    def __init__(self) -> None:
        super().__init__(
            "plc_takeover", "Internet-exposed PLC takeover", "Layers 1-2 (default credentials)",
            "Aliquippa 2023 (Sec. VI-D)",
            "Attacker finds the booster-station PLC on Shodan, logs in with default credentials and stops the "
            "pump. Pressure collapses across the zone.")

    def inject_commands(self, t):
        return [Command("pump", 0.0, "internet", t)]


class ReplayMasking(Attack):
    def __init__(self) -> None:
        super().__init__(
            "replay_masking", "Replay attack masking contamination", "Layer 2 (replay)",
            "JJM risk (Sec. VIII-B): 'report contamination as absent'",
            "A contamination event consumes chlorine while the attacker replays recorded normal readings. "
            "The twin keeps seeing ~1.0 mg/L and never raises dosing.",
            contamination=2.0)
        self.recorded: list[float] = []

    def tamper_packets(self, packets, t):
        pkt = packets[("chlorine", "A")]
        if not self.recorded:
            self.recorded = [1.0 + 0.02 * ((i % 5) - 2) for i in range(30)]
        # replay an old value and rewrite the timestamp so it looks current
        pkt.value = self.recorded[t % len(self.recorded)]


class StealthyDrift(Attack):
    def __init__(self) -> None:
        super().__init__(
            "stealthy_drift", "Stealthy sensor drift", "Layer 1 (physical sensor tampering)",
            "Homaei et al. adversarial evasion (Sec. II-B)",
            "The primary chlorine analyser is physically tampered to under-read by a slowly growing bias "
            "(0.015 mg/L per minute). Every step stays inside range and rate limits.")

    def physical_tamper(self, quantity, channel, value, t, start):
        if quantity == "chlorine" and channel == "A":
            return value - 0.015 * (t - start)
        return value


SCENARIOS: dict[str, type[Attack]] = {
    cls().key: cls
    for cls in (Baseline, ChlorineFDI, PressureFDI, DosingSetpointTamper, PLCTakeover, ReplayMasking, StealthyDrift)
}


def make(key: str) -> Attack:
    try:
        return SCENARIOS[key]()
    except KeyError:
        raise ValueError(f"unknown scenario {key!r}; choose from {', '.join(SCENARIOS)}") from None
