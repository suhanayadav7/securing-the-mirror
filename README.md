# Securing the Mirror

A working implementation and quantitative evaluation of the paper **"Securing the Mirror: A Dual-Use Risk
and Governance Framework for AI-Driven Digital Twins in Water Infrastructure"** (Chaturvedi, Suhana, Sagar,
Joshi; UPES / EY, 2026).

The paper argues that the AI running a water digital twin is also its attack surface. This project turns
the framework into software and tests its claims three ways:

1. **Governance levels under attack.** A control-loop simulator runs six attacks at every maturity level,
   with fallible humans, over hundreds of runs.
2. **Network-scale consequence.** The same attacks are replayed on **C-Town**, a real EPANET hydraulic
   model (via WNTR).
3. **The AI detector as an attack surface.** An ML detector is trained on the real **BATADAL** SCADA
   dataset, then evaded by an adaptive attacker.

| Paper section | In this project |
|---|---|
| IV Risk criteria + four-level maturity scale | `mirror/framework.py` → *Risk scorer* tab, `python -m mirror assess` |
| III Four-layer pipeline | `mirror/twin.py` (plant, signed sensors, AI controller) + `mirror/gateway.py` (Layer 3 controls per level) |
| VI Documented attacks | `mirror/attacks.py` → *Attack simulator* tab, `simulate` / `matrix` / `montecarlo` |
| VI consequences at network scale | `mirror/hydraulics.py` → *Network impact* tab, `python -m mirror network` |
| II-B adversarial ML ("Dark Side of Digital Twins") | `mirror/ml.py` → *ML detector* tab, `python -m mirror ml` |
| V, VIII Case studies, JJM 2.0 | *Case studies* and *Jal Jeevan Mission* tabs |

Paper fixes found while building this are listed in [`PAPER_CORRECTIONS.md`](PAPER_CORRECTIONS.md). It
also contains a ready-to-adapt results section with the numbers below.

## Quick start

Needs **Python 3.10–3.12**. WNTR does not build on 3.13+ yet.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt

.venv/bin/streamlit run app.py                     # dashboard
.venv/bin/python -m mirror assess                  # score Table II handoffs, list priority actions
.venv/bin/python -m mirror matrix                  # every attack x every level (ideal humans)
.venv/bin/python -m mirror montecarlo chlorine_fdi --realistic --runs 200
.venv/bin/python -m mirror network dosing_setpoint_tamper
.venv/bin/python -m mirror ml                      # BATADAL detector + evasion (~15 s)
.venv/bin/python -m pytest -q                      # 41 tests
```

BATADAL data and the C-Town network are downloaded from batadal.net on first use into `data/`. They
are not redistributed.

## Results

### 1. Governance levels under attack

200 runs per cell with **realistic humans**:
- Level 2 operator response: lognormal, median 45 min.
- Level 3 reviewer response: lognormal, median 10 min.
- The Level 3 reviewer wrongly approves 10% of flagged items.

Cells show the % of runs that caused harm:

| Attack (paper link) | L1 | L2 | L3 | L4 |
|---|---|---|---|---|
| False low-chlorine injection (Israel 2020) | 100% | 48.5% | 6.0% | 0% |
| False low-pressure injection (Sec. III) | 100% | 77.5% | 5.5% | 0% |
| 100x dosing setpoint (Oldsmar 2021, Kemuri 2016) | 100% | 96.5% | 0%\* | 0% |
| Internet-exposed PLC takeover (Aliquippa 2023) | 100% | 0% | 0% | 0% |
| Replay masking contamination (JJM risk) | 100% | 100% | 100% | 0%\*\* |
| Stealthy sensor drift (adversarial evasion) | 100% | 100% | 100% | 0% |

\* 9% near misses. \*\* A brief near miss from the contamination event itself, not the attack.

What this shows:
- **Level 2** detects at once but acts late, so harm usually happens anyway.
- **Level 3** stops obvious tampering, but it is only as good as the reviewer.
- **Level 3's range checks miss attacks that stay in range.** Replay and stealthy drift get through;
  only Level 4's signed telemetry and physics cross-checks catch them.
- **Aliquippa is prevented by the Level 1 → 2 hygiene step alone.**

### 2. Network-scale consequence (C-Town, EPANET)

| Level | Setpoint attack in effect | Over-chlorinated water delivered | Junctions > 4 mg/L | Pump attack: demand unserved |
|---|---|---|---|---|
| 1 | 24 h (uncontained) | 18,327 m³ | 333 / 334 | 11,058 m³ (332 junctions < 14 m) |
| 2 | 45 min | 261 m³ | 231 / 334 | 0 (blocked) |
| 3 | 0 (held for review) | 0 | 0 | 0 |
| 4 | 0 (rejected) | 0 | 0 | 0 |

A 45-minute excursion still reaches two-thirds of the network. Tank storage absorbs a 45-minute pump
outage (2 junctions affected), but not a 24-hour one.

### 3. ML detector on BATADAL, and evading it

The detector is an autoencoder ensemble, trained on 8,761 h of normal data and evaluated on 4,177 h
containing 5 labelled attacks:
- **All 5 attacks detected.** Recall 0.63, precision 0.58 (a lower bound, since some attacks in the
  evaluation set are unlabelled), F1 0.60. Single models range from 0.50 to 0.61.

A white-box attacker then rewrites the readings of *k* sensors:

| Sensors controlled | 0 | 3 | 5 | 10 | 20 | 43 | replay last week |
|---|---|---|---|---|---|---|---|
| Recall | 0.63 | 0.45 | 0.14 | 0.02 | 0 | 0 | 0 |
| Attacks detected | 5/5 | 5/5 | 4/5 | 1/5 | 0/5 | 0/5 | 0/5 |

An ML detector alone is at best a Level 3 control. Signed telemetry (Level 4) limits how many
readings an attacker can rewrite.

## How each level is modelled

| Level | Layer 3 gateway |
|---|---|
| 1 Ungoverned | Everything passes through |
| 2 Monitored | Blocks internet-originated commands; logs anomalies; an operator acts after a delay |
| 3 Validated | Range, rate-of-change and command-envelope checks; flagged items are held until a named reviewer verifies them against a field sample |
| 4 Resilient | HMAC-signed packets and commands; redundant sensors cross-checked against the twin's physics model; automatic fail-over and rejection |

## Limitations

- **Control-loop plant.** It is a simplified first-order model, used for timing. The consequence numbers
  come from the EPANET model.
- **EPANET chlorine transport.** EPANET has no longitudinal dispersion, so chlorine slugs arrive
  undiluted and peak concentrations are an upper bound.
- **Human-behaviour parameters** are assumptions and adjustable in the dashboard.
- **Required-level thresholds and JJM scores.** The required-maturity thresholds (ADD ≥ 4 and CS ≥ 4 →
  Level 4; composite ≥ 3 or CS ≥ 4 → Level 3; else Level 2) and the JJM handoff scores are this
  project's reading of the paper's prose.
- **BATADAL labels.** BATADAL dataset04 is only partially labelled.

## Layout

```
mirror/framework.py   criteria, maturity scale, handoff scoring, ranking
mirror/data.py        Tables II-IV and Section VI incidents
mirror/twin.py        plant, signed sensors, PI controller
mirror/gateway.py     Layer 3 controls per level; ideal/realistic humans
mirror/attacks.py     six attack scenarios + baseline
mirror/simulate.py    simulation loop, Monte Carlo
mirror/hydraulics.py  C-Town EPANET consequences (WNTR)
mirror/ml.py          BATADAL autoencoder detector + adversarial evasion
mirror/__main__.py    CLI
app.py                Streamlit dashboard
results/              generated result files quoted above
tests/                pytest suite
```

## Data credits

- **BATADAL and C-Town:** R. Taormina et al., "The Battle Of The Attack Detection ALgorithms: Disclosing
  cyber attacks on water distribution networks," *J. Water Resour. Plann. Manage.*, 144(8), 2018.
  batadal.net.
- **WNTR:** Klise et al., US EPA / Sandia National Laboratories.
