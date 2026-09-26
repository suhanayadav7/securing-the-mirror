"""Datasets from the paper: Table II, Table III, Section VI attacks and Table IV (JJM)."""

from __future__ import annotations

from dataclasses import dataclass

from .framework import Handoff, Maturity

# Table II - illustrative handoffs in a water utility digital twin.
UTILITY_HANDOFFS = [
    Handoff("Water quality (inline sensors)", 5, 2, 4, 5, Maturity.MONITORED),
    Handoff("Pressure/flow (distribution network)", 5, 2, 4, 4, Maturity.MONITORED),
    Handoff("Demand forecasting (scheduling)", 2, 3, 2, 2, Maturity.VALIDATED),
    Handoff("Asset management (pipe data)", 1, 2, 2, 3, Maturity.VALIDATED),
]


@dataclass(frozen=True)
class Deployment:
    name: str
    highest_risk_handoff: str
    composite: float
    maturity: Maturity
    governance_gap: str


# Table III - foreign deployments (composite scores are the paper's estimates).
FOREIGN_DEPLOYMENTS = [
    Deployment("Hong Kong (Reservoir DT)", "Real-time sensor layer", 3.5, Maturity.VALIDATED,
               "No sensor data integrity validation protocol documented"),
    Deployment("Brazil (Integra 4.0)", "Legacy sensor zones", 4.0, Maturity.MONITORED,
               "Heterogeneous validation maturity across network zones"),
    Deployment("Spain (AI Cyber-DT)", "Blockchain scalability", 2.5, Maturity.RESILIENT,
               "Scalability of blockchain validation at national scale"),
]


@dataclass(frozen=True)
class Incident:
    handoff: Handoff
    year: int
    summary: str
    root_cause: str
    scenario: str  # matching simulator scenario


# Section VI - documented attacks rescored against the four criteria.
INCIDENTS = [
    Incident(Handoff("Kemuri Water Company (US)", 4, 5, 4, 5, Maturity.UNGOVERNED), 2016,
             "Attackers pivoted from a payment portal to a shared AS/400 and altered PLC dosing/flow settings.",
             "IT/OT convergence on one legacy system with no segmentation.", "dosing_setpoint_tamper"),
    Incident(Handoff("Israeli Water Sector", 5, 4, 3, 5, Maturity.MONITORED), 2020,
             "Attempted ICS compromise at pumping and wastewater sites, reportedly to raise chlorine levels.",
             "Internet-connected chlorine control reachable with weak/default credentials.", "chlorine_fdi"),
    Incident(Handoff("Oldsmar, Florida (US)", 5, 5, 2, 5, Maturity.MONITORED), 2021,
             "Sodium-hydroxide setpoint briefly raised ~100 ppm -> 11,100 ppm; operator reverted it.",
             "One workstation had unreviewed write access to a safety-critical setpoint.", "dosing_setpoint_tamper"),
    Incident(Handoff("Aliquippa, Pennsylvania (US)", 4, 5, 5, 3, Maturity.UNGOVERNED), 2023,
             "Internet-exposed Unitronics PLC with default credentials disabled at a booster station.",
             "PLC reachable from the internet (Shodan) with default credentials.", "plc_takeover"),
]

# India's Jal Jeevan Mission - handoffs named in Section VIII-B, scored with the framework.
JJM_HANDOFFS = [
    Handoff("JJM in-line water quality -> IMIS/WQMIS", 5, 4, 3, 5, Maturity.MONITORED,
            "Plaintext IoT protocols; false data injection could hide contamination"),
    Handoff("Multi-agency reconciliation (IMIS, WQMIS, CGWB, states)", 3, 4, 2, 4, Maturity.MONITORED,
            "Heterogeneous data-quality standards across agencies (cf. Brazil)"),
    Handoff("Field Testing Kit results (community)", 2, 3, 1, 4, Maturity.MONITORED,
            "Manual entry by trained community testers"),
]

# Table IV - recommended phased governance path for JJM 2.0.
JJM_PHASES = [
    ("Phase 1", "Level 2 -> 3", "12-18 months",
     "Formal schema/range checks for in-line water-quality feeds at IMIS; named district officers review AI-generated alerts."),
    ("Phase 2", "Level 3 -> 4", "24-36 months",
     "Pilot physics-based cross-sensor validation in selected states; lightweight cryptographic signing at LoRaWAN "
     "gateways; evaluate blockchain integrity for quality monitoring."),
    ("Phase 3", "AI integration with governance", "36-60 months from Phase 1",
     "Introduce AI-driven anomaly detection and demand forecasting under a validated Layer 3 framework, with full "
     "audit trail for AI-triggered interventions, aligned to the Panchayat structure."),
]
