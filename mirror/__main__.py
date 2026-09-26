"""Command line: python -m mirror {assess,simulate,matrix}"""

from __future__ import annotations

import argparse
import json
import sys

from .attacks import SCENARIOS, make
from .data import INCIDENTS, JJM_HANDOFFS, UTILITY_HANDOFFS
from .framework import Assessment, Maturity
from .gateway import GatewayConfig
from .simulate import SimConfig, matrix, monte_carlo, run

DATASETS = {
    "utility": UTILITY_HANDOFFS,
    "incidents": [i.handoff for i in INCIDENTS],
    "jjm": JJM_HANDOFFS,
}


def _table(rows: list[dict]) -> str:
    if not rows:
        return "(no rows)"
    cols = list(rows[0])
    fmt = lambda v: "-" if v is None else str(v)
    widths = {c: max(len(c), *(len(fmt(r[c])) for r in rows)) for c in cols}
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    sep = "  ".join("-" * widths[c] for c in cols)
    body = ["  ".join(fmt(r[c]).ljust(widths[c]) for c in cols) for r in rows]
    return "\n".join([line, sep, *body])


def cmd_assess(args: argparse.Namespace) -> None:
    assessment = Assessment(DATASETS[args.dataset])
    if args.json:
        print(json.dumps(assessment.to_rows(), indent=2))
        return
    print(_table(assessment.to_rows()))
    for h in assessment.priority_gaps():
        print(f"\n{h.name}: Level {int(h.maturity)} -> Level {int(h.required_maturity)} "
              f"(composite {h.composite:.2f}, {h.risk_band})")
        for rec in h.recommendations():
            print(f"  - {rec}")


def _config(args: argparse.Namespace) -> SimConfig:
    if args.realistic:
        humans = GatewayConfig.realistic(args.operator_delay, args.review_delay, args.miss_rate)
    else:
        humans = GatewayConfig(args.operator_delay, args.review_delay)
    return SimConfig(duration=args.duration, attack_start=args.attack_start, seed=args.seed, gateway=humans)


def cmd_simulate(args: argparse.Namespace) -> None:
    attack = make(args.scenario)
    result = run(args.scenario, args.level, _config(args))
    if args.json:
        print(json.dumps({**result.summary(), "alerts": result.alerts}, indent=2))
        return
    print(f"{attack.title}  [{attack.layer}]  - {attack.paper_ref}")
    print(attack.description, "\n")
    for k, v in result.summary().items():
        print(f"  {k:20} {'-' if v is None else v}")
    print("\nAlert log (first 10):")
    for t, msg in result.alerts[:10]:
        print(f"  t={t:>3}  {msg}")
    if len(result.alerts) > 10:
        print(f"  ... {len(result.alerts) - 10} more")


def cmd_matrix(args: argparse.Namespace) -> None:
    rows = [r.summary() for r in matrix([s for s in SCENARIOS if s != "baseline"], _config(args))]
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    keep = ("scenario", "level", "outcome", "detected_after_min", "contained_after_min", "unsafe_min")
    print(_table([{k: r[k] for k in keep} for r in rows]))


def cmd_montecarlo(args: argparse.Namespace) -> None:
    cfg = _config(args)
    rows = [monte_carlo(args.scenario, level, cfg, args.runs) for level in Maturity]
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    humans = "realistic" if args.realistic else "ideal"
    print(f"{make(args.scenario).title}: {args.runs} runs per level, {humans} humans\n")
    print(_table(rows))


def cmd_ml(args: argparse.Namespace) -> None:
    from .ml import run_experiment  # heavy imports only when needed
    result = run_experiment()
    if args.save:
        with open(args.save, "w") as f:
            json.dump(result, f)
    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k not in ("score", "labels", "time")}, indent=2))
        return
    c = result["clean"]
    print(f"BATADAL: {result['dataset']['train_hours']} h normal training data, "
          f"{result['dataset']['eval_hours']} h evaluation with {result['dataset']['labelled_attacks']} labelled attacks")
    print(f"Autoencoder ensemble: precision {c['precision']:.2f}  recall {c['recall']:.2f}  F1 {c['f1']:.2f}  "
          f"attacks detected {c['attacks_detected']}/{c['attacks_total']}  (single-seed F1 "
          f"{min(result['single_seed_f1']):.2f}-{max(result['single_seed_f1']):.2f})")
    print("(precision is a lower bound: dataset04 leaves some attacks unlabelled)\n")
    print("Adaptive attacker who controls k sensor readings:")
    print(_table(result["adversarial"]))
    r = result["replay"]
    print(f"\nReplay of last week's readings: recall {r['recall']:.2f}, attacks detected "
          f"{r['attacks_detected']}/{r['attacks_total']}")


def cmd_network(args: argparse.Namespace) -> None:
    from .hydraulics import impact_by_level
    rows = []
    for level, impact in impact_by_level(args.scenario, _config(args), args.uncontained_hours).items():
        rows.append({"level": int(level), **impact.as_dict()})
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    unit = "m3 over-chlorinated water delivered" if args.scenario == "dosing_setpoint_tamper" else "m3 demand unserved"
    print(f"{make(args.scenario).title} on C-Town (EPANET) - harmful volume = {unit}\n")
    keep = ("level", "attack_minutes", "nodes_affected", "demand_nodes", "first_harm_h", "harm_hours",
            "harmful_volume_m3")
    print(_table([{k: r[k] for k in keep} for r in rows]))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="mirror", description="Securing the Mirror - digital twin risk toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assess", help="score data handoffs and list governance gaps")
    a.add_argument("--dataset", choices=DATASETS, default="utility")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_assess)

    commands = (("simulate", cmd_simulate, "run one attack at one maturity level"),
                ("matrix", cmd_matrix, "run every attack at every maturity level"),
                ("montecarlo", cmd_montecarlo, "repeat one attack over many seeds at every level"),
                ("network", cmd_network, "replay an attack on the C-Town EPANET network"))
    for name, func, help_ in commands:
        s = sub.add_parser(name, help=help_)
        if name == "simulate":
            s.add_argument("scenario", choices=SCENARIOS)
            s.add_argument("--level", type=int, choices=[int(m) for m in Maturity], default=2)
        elif name == "montecarlo":
            s.add_argument("scenario", choices=SCENARIOS)
            s.add_argument("--runs", type=int, default=200)
        elif name == "network":
            s.add_argument("scenario", choices=("dosing_setpoint_tamper", "plc_takeover"))
            s.add_argument("--uncontained-hours", type=float, default=24,
                           help="how long an attack nobody contains keeps going")
        s.add_argument("--duration", type=int, default=360)
        s.add_argument("--attack-start", type=int, default=60)
        s.add_argument("--seed", type=int, default=7)
        s.add_argument("--operator-delay", type=int, default=45, help="Level 2 response time (min)")
        s.add_argument("--review-delay", type=int, default=10, help="Level 3 reviewer time (min)")
        s.add_argument("--realistic", action="store_true",
                       help="variable human response times and a fallible Level 3 reviewer")
        s.add_argument("--miss-rate", type=float, default=0.1, help="Level 3 reviewer miss rate (with --realistic)")
        s.add_argument("--json", action="store_true")
        s.set_defaults(func=func)

    m = sub.add_parser("ml", help="train/evaluate the BATADAL detector and attack it")
    m.add_argument("--save", help="write full results JSON to this path")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_ml)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
