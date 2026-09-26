"""Securing the Mirror - interactive dashboard.  Run:  streamlit run app.py"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from mirror.attacks import SCENARIOS, make
from mirror.data import FOREIGN_DEPLOYMENTS, INCIDENTS, JJM_HANDOFFS, JJM_PHASES, UTILITY_HANDOFFS
from mirror.framework import CRITERIA, MATURITY_INFO, Assessment, Handoff, Maturity
from mirror.gateway import GatewayConfig
from mirror.simulate import SimConfig, monte_carlo, run
from mirror.twin import CHLORINE_SAFE, PRESSURE_SAFE

# Reference data-viz palette: categorical slots in fixed order, status colours reserved for state.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
STATUS = {"Safe": "#0ca30c", "Near miss": "#fab219", "Harm": "#d03b3b"}
STATUS_ICON = {"Safe": "✓", "Near miss": "!", "Harm": "✕"}
BAND_GRAY = "rgba(128,128,128,0.12)"

st.set_page_config(page_title="Securing the Mirror", page_icon="💧", layout="wide")
st.title("Securing the Mirror")
st.caption("Dual-use risk and governance framework for AI-driven digital twins in water infrastructure")

tab_score, tab_sim, tab_net, tab_ml, tab_cases, tab_jjm, tab_about = st.tabs(
    ["Risk scorer", "Attack simulator", "Network impact (C-Town)", "ML detector (BATADAL)", "Case studies",
     "Jal Jeevan Mission", "Framework"])


@st.cache_data(show_spinner=False)
def cached_monte_carlo(scenario: str, cfg: SimConfig, runs: int) -> list[dict]:
    return [monte_carlo(scenario, level, cfg, runs) for level in Maturity]


@st.cache_data(show_spinner=False)
def cached_network(scenario: str, cfg: SimConfig, uncontained_hours: float) -> dict[int, dict]:
    from mirror.hydraulics import impact_by_level
    return {int(k): {**v.as_dict(), "t": v.series_t_h, "affected": v.series_affected}
            for k, v in impact_by_level(scenario, cfg, uncontained_hours).items()}


@st.cache_data(show_spinner=False)
def cached_ml() -> dict:
    from mirror.ml import run_experiment
    return run_experiment()


def style(fig: go.Figure, height: int = 360) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=90, b=10),
                      legend=dict(orientation="h", yanchor="bottom", y=1.04, x=0), hovermode="x unified")
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor="rgba(128,128,128,0.15)")
    return fig


def handoffs_frame(handoffs: list[Handoff]) -> pd.DataFrame:
    return pd.DataFrame([{"Handoff": h.name, "DFD": h.dfd, "VM": h.vm, "ADD": h.add, "CS": h.cs,
                          "Current level": int(h.maturity)} for h in handoffs])


# ---------------------------------------------------------------------------------------- scorer
with tab_score:
    st.subheader("Score your data handoffs")
    st.write("Each handoff is scored 1 (low risk) to 5 (high risk) on four criteria; the composite is "
             "their mean. Edit the table, add rows, or load a preset.")
    preset = st.radio("Preset", ["Water utility (Table II)", "Jal Jeevan Mission", "Documented attacks (Sec. VI)"],
                      horizontal=True)
    base = {"Water utility (Table II)": UTILITY_HANDOFFS, "Jal Jeevan Mission": JJM_HANDOFFS,
            "Documented attacks (Sec. VI)": [i.handoff for i in INCIDENTS]}[preset]

    score_cfg = {k.upper(): st.column_config.NumberColumn(k.upper(), help=f"{name}: {desc}", min_value=1,
                                                          max_value=5, step=1, required=True)
                 for k, (name, desc) in CRITERIA.items()}
    edited = st.data_editor(
        handoffs_frame(base), num_rows="dynamic", width="stretch", key=f"editor-{preset}",
        column_config={**score_cfg, "Current level": st.column_config.NumberColumn(
            "Current level", help="Governance maturity 1-4", min_value=1, max_value=4, step=1, required=True)})

    handoffs = []
    for row in edited.dropna().to_dict("records"):
        try:
            handoffs.append(Handoff(str(row["Handoff"]), int(row["DFD"]), int(row["VM"]), int(row["ADD"]),
                                    int(row["CS"]), Maturity(int(row["Current level"]))))
        except ValueError as e:
            st.warning(f"Skipped {row['Handoff']}: {e}")

    if handoffs:
        assessment = Assessment(handoffs)
        c1, c2, c3 = st.columns(3)
        c1.metric("Handoffs assessed", len(handoffs))
        c2.metric("Below required maturity", len(assessment.priority_gaps()))
        c3.metric("Highest composite risk", f"{max(h.composite for h in handoffs):.2f} / 5")

        ordered = sorted(handoffs, key=lambda h: h.composite, reverse=True)
        fig = go.Figure(go.Bar(
            x=[h.name for h in ordered], y=[h.composite for h in ordered], marker_color=SERIES[0],
            text=[f"{h.composite:.2f} · L{int(h.maturity)}" for h in ordered], textposition="outside",
            hovertemplate="%{x}<br>Composite %{y:.2f}<extra></extra>", marker_cornerradius=4))
        fig.add_hline(y=3.5, line_dash="dot", line_color="gray",
                      annotation_text="High-risk threshold (3.5)", annotation_position="top right")
        fig.update_yaxes(range=[0, 5.4], title="Composite risk (1-5)")
        fig.update_layout(title="Composite risk by handoff (label: score · current level)", hovermode="closest")
        st.plotly_chart(style(fig), width="stretch")

        st.dataframe(pd.DataFrame(assessment.to_rows()), width="stretch", hide_index=True)

        gaps = assessment.priority_gaps()
        if gaps:
            st.markdown("#### Priority actions")
            for h in gaps:
                with st.expander(f"{h.name}: Level {int(h.maturity)} → Level {int(h.required_maturity)} "
                                 f"({h.risk_band}, {h.composite:.2f})", expanded=h is gaps[0]):
                    for rec in h.recommendations():
                        st.markdown(f"- {rec}")
        else:
            st.success("Every handoff meets its required maturity level.")

# ------------------------------------------------------------------------------------- simulator
with tab_sim:
    st.subheader("What each governance level does to the same attack")
    left, right = st.columns([2, 1])
    with left:
        key = st.selectbox("Attack scenario", [k for k in SCENARIOS if k != "baseline"] + ["baseline"],
                           format_func=lambda k: make(k).title)
    attack = make(key)
    with right:
        with st.popover("Simulation settings"):
            duration = st.slider("Duration (min)", 120, 720, 360, 30)
            attack_start = st.slider("Attack starts at (min)", 10, 120, 60, 5)
            operator_delay = st.slider("Level 2 operator response (min)", 5, 240, 45, 5)
            review_delay = st.slider("Level 3 reviewer response (min)", 1, 60, 10, 1)
            humans = st.radio("Human model", ["Ideal", "Realistic"], horizontal=True,
                              help="Realistic: response times vary (lognormal around the values above) and the "
                                   "Level 3 reviewer sometimes approves a bad item.")
            miss_rate = st.slider("Level 3 reviewer miss rate", 0.0, 0.5, 0.1, 0.05,
                                  disabled=humans == "Ideal")
            seed = st.number_input("Random seed", value=7, step=1)
    st.markdown(f"**{attack.layer}** · paper: {attack.paper_ref}  \n{attack.description}")

    humans_cfg = (GatewayConfig.realistic(operator_delay, review_delay, miss_rate) if humans == "Realistic"
                  else GatewayConfig(operator_delay, review_delay))
    cfg = SimConfig(duration, attack_start, int(seed), humans_cfg)
    results = {level: run(key, level, cfg) for level in Maturity}

    cols = st.columns(4)
    for col, (level, r) in zip(cols, results.items()):
        with col:
            st.markdown(f"**{level.label}**")
            st.markdown(f"<span style='color:{STATUS[r.outcome]};font-weight:600'>{STATUS_ICON[r.outcome]} "
                        f"{r.outcome}</span>", unsafe_allow_html=True)
            st.caption(f"Detected: {'—' if r.detected_after is None else f'+{r.detected_after} min'}  \n"
                       f"Contained: {'—' if r.contained_after is None else f'+{r.contained_after} min'}  \n"
                       f"Unsafe: {r.unsafe_minutes} min")

    quantity = "pressure" if key in ("pressure_fdi", "plc_takeover") else "chlorine"
    unit, band = ("psi", PRESSURE_SAFE) if quantity == "pressure" else ("mg/L", CHLORINE_SAFE)
    fig = make_subplots(rows=2, cols=2, shared_xaxes=True, vertical_spacing=0.12,
                        subplot_titles=[lvl.label for lvl in Maturity])
    for i, (level, r) in enumerate(results.items()):
        row, col = i // 2 + 1, i % 2 + 1
        t = [p["t"] for p in r.trace]
        fig.add_trace(go.Scatter(x=t, y=[p[f"{quantity}_true"] for p in r.trace], name="True value",
                                 line=dict(color=SERIES[0], width=2), legendgroup="true", showlegend=i == 0),
                      row=row, col=col)
        fig.add_trace(go.Scatter(x=t, y=[p[f"{quantity}_seen"] for p in r.trace], name="What the AI sees",
                                 line=dict(color=SERIES[1], width=2, dash="dash"), legendgroup="seen",
                                 showlegend=i == 0), row=row, col=col)
    # shapes go on after the traces: plotly skips subplots that are still empty
    fig.add_hrect(y0=band[0], y1=band[1], fillcolor=BAND_GRAY, line_width=0, row="all", col="all")
    fig.add_vline(x=attack_start, line_dash="dot", line_color="gray", row="all", col="all")
    peak = max(max(p[f"{quantity}_true"], p[f"{quantity}_seen"]) for r in results.values() for p in r.trace)
    fig.update_yaxes(range=[0, max(peak, band[1]) * 1.08])  # one scale across all four panels
    fig.update_layout(title=f"{quantity.title()} ({unit}) · shaded = safe band · dotted = attack start")
    fig.update_xaxes(title_text="minutes", row=2)
    st.plotly_chart(style(fig, 560), width="stretch")

    level_for_log = st.radio("Alert log for", list(Maturity), format_func=lambda m: m.label, horizontal=True,
                             index=2)
    alerts = results[level_for_log].alerts
    if alerts:
        st.dataframe(pd.DataFrame(alerts, columns=["minute", "alert"]), width="stretch",
                     hide_index=True, height=240)
    else:
        st.info("No alerts were raised at this level.")

    st.markdown("#### How reliable is each level?")
    st.caption("One run is one story. Repeat the attack over many seeds - sensor noise and, with the realistic "
               "human model, response times and reviewer mistakes all vary.")
    runs = st.select_slider("Runs per level", [50, 100, 200, 500], value=100)
    if st.button("Run Monte Carlo", type="primary"):
        with st.spinner(f"Running {runs * 4} simulations..."):
            mc = cached_monte_carlo(key, cfg, runs)
        fig = go.Figure()
        labels = [Maturity(r["level"]).label for r in mc]
        for outcome, field_ in (("Safe", "p_safe"), ("Near miss", "p_near_miss"), ("Harm", "p_harm")):
            fig.add_trace(go.Bar(y=labels, x=[r[field_] * 100 for r in mc], name=outcome, orientation="h",
                                 marker=dict(color=STATUS[outcome], line=dict(width=2, color="white")),
                                 text=[f"{STATUS_ICON[outcome]} {r[field_] * 100:.0f}%" if r[field_] >= 0.06 else ""
                                       for r in mc], textposition="inside",
                                 hovertemplate=f"{outcome}: %{{x:.1f}}%<extra></extra>"))
        fig.update_layout(barmode="stack", title=f"Outcome over {runs} runs ({humans.lower()} humans)",
                          hovermode="closest")
        fig.update_xaxes(title="% of runs", range=[0, 100])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(style(fig, 300), width="stretch")
        st.dataframe(pd.DataFrame(mc).drop(columns=["scenario"]), width="stretch", hide_index=True)

    with st.expander("Full matrix: every attack × every level"):
        rows = [run(s, lvl, cfg).summary() for s in SCENARIOS if s != "baseline" for lvl in Maturity]
        df = pd.DataFrame(rows).pivot(index="scenario", columns="level", values="outcome")
        df.columns = [f"Level {c}" for c in df.columns]
        st.dataframe(df.map(lambda o: f"{STATUS_ICON[o]} {o}"), width="stretch")

# -------------------------------------------------------------------------------------- network
with tab_net:
    st.subheader("From containment time to network damage")
    st.write("The attack simulator tells us how long a tampered command stays in effect at each level. Here "
             "that duration is replayed on **C-Town**, the EPANET model behind the BATADAL dataset (388 "
             "junctions, 7 tanks, 11 pumps), to see how far the damage spreads.")
    c1, c2 = st.columns([2, 1])
    with c1:
        net_key = st.selectbox("Scenario", ["dosing_setpoint_tamper", "plc_takeover"],
                               format_func=lambda k: make(k).title + {"dosing_setpoint_tamper": " (Oldsmar)",
                                                                       "plc_takeover": " (Aliquippa)"}[k])
    with c2:
        uncontained = st.slider("An uncontained attack lasts (h)", 2, 48, 24,
                                help="Level 1 never detects the attack; assume it runs this long before "
                                     "someone notices from outside the control system.")
    net_cfg = SimConfig(gateway=GatewayConfig(operator_delay, review_delay))
    with st.spinner("Running EPANET simulations..."):
        impacts = cached_network(net_key, net_cfg, uncontained)
    dosing = net_key == "dosing_setpoint_tamper"
    volume_label = "Over-chlorinated water delivered (m³)" if dosing else "Demand left unserved (m³)"
    harm_label = "junctions above 4 mg/L chlorine" if dosing else "junctions below 14 m (~20 psi)"

    cols = st.columns(4)
    for col, (lvl, imp) in zip(cols, impacts.items()):
        with col:
            st.markdown(f"**{Maturity(lvl).label}**")
            st.metric(volume_label, f"{imp['harmful_volume_m3']:,.0f}")
            st.caption(f"Attack in effect: {imp['attack_minutes']} min  \n"
                       f"Junctions harmed: {imp['nodes_affected']} / {imp['demand_nodes']}  \n"
                       f"Hours with harm: {imp['harm_hours']}")
    fig = go.Figure()
    for i, (lvl, imp) in enumerate(impacts.items()):
        fig.add_trace(go.Scatter(x=imp["t"], y=imp["affected"], name=Maturity(lvl).label,
                                 line=dict(color=SERIES[i], width=2)))
    fig.add_vline(x=0, line_dash="dot", line_color="gray", annotation_text="attack starts")
    fig.update_layout(title=f"Number of {harm_label} over time (Levels at zero overlap)")
    fig.update_xaxes(title="hours after attack start")
    fig.update_yaxes(title="junctions harmed", rangemode="tozero")
    st.plotly_chart(style(fig, 380), width="stretch")
    st.caption("EPANET via WNTR, pressure-driven demand, 15-minute steps, first-order chlorine decay "
               "(-0.5/day). EPANET's water-quality model has no longitudinal dispersion, so a chlorine slug "
               "arrives undiluted - peak concentrations are an upper bound.")

# ------------------------------------------------------------------------------------------- ML
with tab_ml:
    st.subheader("The twin's AI detector - and how an attacker blinds it")
    st.write("An autoencoder ensemble trained on one year of normal C-Town SCADA data (**BATADAL**, 43 "
             "sensors, hourly) and evaluated on six months containing labelled attacks. Then a white-box "
             "attacker rewrites the readings of *k* sensors to hide the attacks (paper Sec. II-B).")
    with st.spinner("Training detector and running evasion attacks (first load ~15 s)..."):
        res = cached_ml()
    c = res["clean"]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Attacks detected", f"{c['attacks_detected']} / {c['attacks_total']}")
    m2.metric("Recall (attack hours)", f"{c['recall']:.0%}")
    m3.metric("Precision", f"{c['precision']:.0%}", help="Lower bound: dataset04 leaves some attacks unlabelled.")
    m4.metric("F1", f"{c['f1']:.2f}", help=f"Single-seed F1 ranges {min(res['single_seed_f1']):.2f}-"
                                           f"{max(res['single_seed_f1']):.2f}; the ensemble is reported.")

    fig = go.Figure()
    t, score, lab = res["time"], res["score"], res["labels"]
    fig.add_trace(go.Scatter(x=t, y=score, name="Anomaly score", line=dict(color=SERIES[0], width=1.5)))
    from mirror.ml import attack_windows
    for a, b in attack_windows([bool(v) for v in lab]):
        fig.add_vrect(x0=t[a], x1=t[b], fillcolor="rgba(208,59,59,0.18)", line_width=0)
    fig.add_trace(go.Scatter(x=[t[0], t[-1]], y=[res["threshold"]] * 2, mode="lines", hoverinfo="skip",
                             name="Threshold (99.5th pct of normal)", line=dict(color="gray", dash="dot")))
    fig.update_yaxes(type="log", title="reconstruction error (log)")
    fig.update_layout(title="Detector output on BATADAL dataset04 · shaded = labelled attacks")
    st.plotly_chart(style(fig, 360), width="stretch")

    adv = pd.DataFrame(res["adversarial"])
    fig = go.Figure(go.Scatter(x=adv["sensors_controlled"], y=adv["recall"] * 100, mode="lines+markers",
                               line=dict(color=SERIES[0], width=2), marker=dict(size=9),
                               text=[f"{a}/5 attacks" for a in adv["attacks_detected"]],
                               hovertemplate="%{x} sensors controlled<br>recall %{y:.0f}%<br>%{text}<extra></extra>"))
    fig.update_layout(title="Detection recall vs number of sensor readings the attacker controls",
                      hovermode="closest")
    fig.update_xaxes(title="sensors controlled (of 43)")
    fig.update_yaxes(title="recall (% of attack hours)", range=[0, 100])
    st.plotly_chart(style(fig, 340), width="stretch")
    r = res["replay"]
    st.markdown(
        f"**What this means.** With plaintext telemetry (Levels 1-3) an attacker on the network can rewrite "
        f"any reading, and controlling ~10 of 43 is enough to hide almost every attack hour. Simply replaying "
        f"last week's readings drops recall to **{r['recall']:.0%}**. An ML detector alone is therefore a "
        f"Level 3 control at best. Level 4's signed packets confine the attacker to sensors they physically "
        f"tamper with, and redundant sensors cross-checked against the physics model catch that too - see "
        f"*Stealthy sensor drift* in the simulator.")
    st.caption(f"Most useful sensors for the attacker: {', '.join(res['top_sensors'])}. "
               "Data: Taormina et al., 'The Battle of the Attack Detection Algorithms', J. Water Resour. Plann. "
               "Manage., 2018.")

# ---------------------------------------------------------------------------------------- cases
with tab_cases:
    st.subheader("Foreign deployments (Section V)")
    st.dataframe(pd.DataFrame([{"Deployment": d.name, "Highest-risk handoff": d.highest_risk_handoff,
                                "Composite (est.)": d.composite, "Maturity": d.maturity.label,
                                "Primary governance gap": d.governance_gap} for d in FOREIGN_DEPLOYMENTS]),
                 width="stretch", hide_index=True)
    fig = go.Figure(go.Scatter(
        x=[int(d.maturity) for d in FOREIGN_DEPLOYMENTS], y=[d.composite for d in FOREIGN_DEPLOYMENTS],
        mode="markers+text", text=[d.name for d in FOREIGN_DEPLOYMENTS], textposition="top center",
        marker=dict(size=14, color=SERIES[0], line=dict(width=2, color="white")),
        hovertemplate="%{text}<br>Level %{x} · composite %{y}<extra></extra>"))
    fig.update_xaxes(title="Governance maturity level", range=[0.5, 4.5], tickvals=[1, 2, 3, 4], showgrid=True)
    fig.update_yaxes(title="Composite risk (est.)", range=[1, 5])
    fig.update_layout(title="Maturity vs risk: higher maturity does not automatically mean lower risk",
                      hovermode="closest")
    st.plotly_chart(style(fig), width="stretch")

    st.subheader("Documented attacks rescored (Section VI)")
    fig = go.Figure()
    names = [f"{i.handoff.name} ({i.year})" for i in INCIDENTS]
    for n, key_ in enumerate(CRITERIA):
        fig.add_trace(go.Bar(name=key_.upper(), x=names, y=[i.handoff.scores[key_] for i in INCIDENTS],
                             marker_color=SERIES[n], marker_cornerradius=4,
                             hovertemplate=f"{CRITERIA[key_][0]}: %{{y}}<extra></extra>"))
    fig.update_layout(barmode="group", bargap=0.25, bargroupgap=0.08,
                      title="All four cluster at composite 4.25-4.5 and Level 1-2 maturity")
    fig.update_yaxes(title="Score (1-5)", range=[0, 5.3])
    st.plotly_chart(style(fig), width="stretch")
    for inc in INCIDENTS:
        with st.expander(f"{inc.handoff.name} ({inc.year}) · composite {inc.handoff.composite:.2f} · "
                         f"{inc.handoff.maturity.label}"):
            st.markdown(f"**What happened:** {inc.summary}  \n**Root cause:** {inc.root_cause}  \n"
                        f"**Replay it:** Attack simulator → *{make(inc.scenario).title}*")

# ------------------------------------------------------------------------------------------- JJM
with tab_jjm:
    st.subheader("Jal Jeevan Mission 2.0: governance before AI")
    st.write("JJM already has Layers 1-3 (IoT sensors, IMIS/WQMIS) but no Layer 4 AI decision loop. "
             "Governance can be designed before autonomous AI is switched on.")
    st.dataframe(pd.DataFrame(JJM_PHASES, columns=["Phase", "Maturity transition", "Timeline", "Actions"]),
                 width="stretch", hide_index=True)
    st.markdown("#### JJM handoffs, scored")
    st.caption("Illustrative scores derived from the risks named in Section VIII-B, not measurements.")
    st.dataframe(pd.DataFrame(Assessment(JJM_HANDOFFS).to_rows()), width="stretch", hide_index=True)

# ------------------------------------------------------------------------------------- framework
with tab_about:
    st.subheader("Risk criteria")
    st.table(pd.DataFrame([{"Code": k.upper(), "Criterion": n, "Scale": d} for k, (n, d) in CRITERIA.items()]))
    st.subheader("Four-level governance maturity scale")
    st.table(pd.DataFrame([{"Level": m.label, "Description": i["description"], "Technical equivalent": i["technical"]}
                           for m, i in MATURITY_INFO.items()]))
    st.subheader("How the simulator models each level")
    st.markdown("""
- **Level 1**: readings and commands pass straight through to the AI and the plant.
- **Level 2**: internet-originated commands are blocked (no exposure, no default credentials). Out-of-range
  readings and commands are *logged*; an operator acts after the configured response time.
- **Level 3**: range, rate-of-change and command-envelope checks. Flagged items are **held** and a named reviewer
  checks them against a field sample after the review delay.
- **Level 4**: HMAC-signed sensor packets and controller commands, two independent sensors cross-checked against
  the twin's physics model, automatic fail-over and rejection of unsigned commands.
""")
