# Corrections for "Securing the Mirror" (Desktop version, 27 Sep 2026)

Checked against `Securing_the_Mirror (1).pdf`. Only the PDF is available, so these are
find-and-replace instructions for the Word/LaTeX source.

## A. Citation errors (fix before submitting)

A script cross-checked every in-text citation against the reference list:

- **Cited but not in the list:** [30], [32], [33], [35]. The list ends at [29].
- **In the list but never cited:** [9], [14], [15], [18]\*, [21], [25], [27], [28], [29].
  (\*[18] is cited once, in VIII-A.)

The uncited [25], [27], [28] and [29] are the correct sources for Section VI. The Section VI
citations appear to have been renumbered from an older draft.

| # | Where | Current | Replace with |
|---|---|---|---|
| 1 | VI-B Israel, "What happened" | `[30], [32]` | `[27], [28]` |
| 2 | VI-B Israel, second wave | `[35]` | `[27]` (check it covers the June 2020 Galilee wave) |
| 3 | VI-B Israel, "close to successful" | `[35]` | the source that contains this quote: [27] or [28]. If neither does, add the article it came from |
| 4 | VI-B Israel, password reset | `[32], [33]` | `[28]` (or add the Israel National Cyber Directorate advisory as a new reference) |
| 5 | VI-C Oldsmar, "What happened" | `[6], [3]` | `[25]` ([6] is Rousso et al. and [3] is Homaei et al., both digital-twin papers) |
| 6 | VI-C Oldsmar, "24–36 hours to reach a tap" | `[3]` | `[25]`, or add the Pinellas County Sheriff's Office statement (Feb 2021) as a primary source |
| 7 | VI-C Oldsmar, revised account | `[4], [7]` | `[25]` |
| 8 | VI-D Aliquippa, "What happened" | `[10], [11], [16]` | `[16], [29]` ([11] is the AWWA digital-twins page) |
| 9 | VI-D Aliquippa, manual operation / CISA | `[17]` (twice) | `[29]` ([17] is the Jal Jeevan Mission portal). Consider adding CISA advisory AA23-335A (Dec 2023) on Unitronics PLCs; verify the number before citing |
| 10 | II-A | "Spain's National Institute of Cybersecurity [3] introduce…" | "Homaei et al. [3] introduce…" ([3] is authored by Homaei et al.) |
| 11 | II-B | "Al-Rubaye et al. [5] document weak encryption, poor authentication, and outdated protocols…" | cite **[21]** here: its title is exactly this claim. Keep [5] only if it also makes the claim |
| 12 | Reference list | [9], [14], [15] | cite them where relevant (e.g. [9] IWMI in V-B, developing-country context) or delete them |

## B. Content inconsistencies

| # | Where | Problem | Fix |
|---|---|---|---|
| 13 | I-A Scope and Limitations | Second bullet reads "Scope: digital twins in manufacturing…", which is the opposite of what is meant | Change to "**Out of scope:** digital twins in manufacturing, energy grids, or transportation, except where…" |
| 14 | V-C vs Table III | V-C text says Spain is "Estimated maturity: **Level 3**"; Table III says **Level 4** | Pick one. V-C's own argument ("no formal human-in-loop validation") fits Level 3; Fig. 4's caption fits Level 4. If Level 4, change the V-C sentence |
| 15 | Fig. 5 caption | "cluster at composite risk 4.0–4.5" | The scores are 4.25–4.5; write "4.25–4.5". Also fix the grammar: "the same combination **that** Section IV-D identifies" |
| 16 | VI-A Kemuri | "Layer 3 network segmentation (Section III-A)" | Segmentation is a Layer 2 (network) control in your own Section III-A: "Layer 2 network segmentation" |
| 17 | Fig. 4 | Two y-axes (maturity bars + risk line) | Dual axes make the two series look correlated by construction. Use a scatter plot (maturity on x, composite on y), as in the project's *Case studies* tab |
| 18 | Abstract / I (contributions) | Claims validation, but everything is illustrative estimates | After adding Section VI-F below, add to the contributions: "…and a quantitative evaluation on the BATADAL benchmark and the C-Town hydraulic network" |

## C. Suggested new subsection: VI-F Experimental Validation

Every number below comes from this repository (`results/*.json`) and can be regenerated with the
commands in the README. Adjust the wording to your style.

> **F. Experimental Validation**
>
> To move beyond illustrative scores, we implemented the framework as an open-source toolkit and evaluated
> it in three ways.
>
> *1) Governance levels under attack.* A minute-resolution control-loop model of a treatment plant (chlorine
> dosing and pumping under PI control, two independent HMAC-signing sensors per quantity) was attacked with
> six scenarios mapped to Sections III and VI: false-data injection on chlorine and pressure, a 100× dosing
> setpoint change (Oldsmar/Kemuri), an internet-exposed PLC takeover (Aliquippa), a replay attack masking
> contamination, and stealthy sensor drift. Each maturity level was implemented as the controls in Table I.
> We used fallible humans: lognormal response times (Level 2 median 45 min, Level 3 median 10 min) and a
> Level 3 reviewer who wrongly approves 10% of flagged items. Over 200 runs per cell, Level 2 still produced
> harm in 48.5% (chlorine injection), 77.5% (pressure injection) and 96.5% (setpoint tampering) of runs,
> because it detects immediately but acts late. Level 3 reduced this to 6.0%, 5.5% and 0%. Level 4
> prevented harm in every run. Two attacks separate Level 3 from Level 4. Replay and stealthy drift stay
> within the range and rate limits, so they evaded Level 3 in 100% of runs. Level 4's signature and
> cross-sensor checks contained them in every run (within 17 minutes for drift). The Aliquippa scenario
> was stopped by the Level 1→2 transition alone.
>
> *2) Network-scale consequence.* The containment time at each level was replayed on C-Town, the EPANET
> model behind the BATADAL benchmark (388 junctions, 7 tanks, 11 pumps), using pressure-driven hydraulics
> and chlorine transport. An uncontained setpoint attack (Level 1, assumed to last 24 h) delivered
> 18,327 m³ of water above 4 mg/L chlorine to 333 of 334 demand junctions. At Level 2 the attack lasted
> 45 minutes and still delivered 261 m³ to 231 junctions: a short excursion spreads widely. At Levels 3–4
> no over-chlorinated water was delivered. A 24-hour shutdown of the main pumping station left 11,058 m³
> of demand unserved and dropped 332 junctions below 14 m of pressure. Tank storage absorbed a 45-minute
> outage (2 junctions affected), so containment time, not just detection, drives consequence.
>
> *3) The AI detector as an attack surface.* An autoencoder ensemble was trained on one year of normal
> BATADAL SCADA data (43 sensors) and evaluated on the labelled attack dataset. It detected all 5 labelled
> attacks, with hourly recall 0.63, precision 0.58 and F1 0.60 (single models: F1 0.50–0.61). Precision is
> a lower bound, because the dataset leaves some attacks unlabelled. A white-box attacker then optimised
> the readings of the *k* sensors most useful to them. Recall fell to 0.14 with k = 5 and 0.02 with
> k = 10; with k ≥ 20 no attack was detected. Replaying the previous week's readings also reduced recall
> to zero. This reproduces the adversarial vulnerability reported by Homaei et al. [4] on real SCADA
> data. It also shows why an ML detector alone is at best a Level 3 control. Level 4's signed telemetry
> confines the attacker to physically tampered sensors, and redundant sensors checked against the
> physics model catch those.

Limitations to state alongside it:
- The plant model is simplified.
- EPANET has no longitudinal dispersion, so peak chlorine concentrations are an upper bound.
- Human-behaviour parameters are assumptions.
- The required-maturity thresholds are the authors' operationalisation of Section IV.
