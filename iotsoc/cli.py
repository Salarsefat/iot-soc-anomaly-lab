"""Command line: python -m iotsoc <command> [options]

  run       full offline experiment (simulate -> train -> calibrate -> test -> report)
  train     fit and save the model bundle used by live mode
  replay    write the 2-hour demo stream into a log file that Wazuh watches
  live      follow Wazuh archives.json, score windows, write ML alerts for Wazuh
  demo      replay + live together (what you show in the workshop)
  samples   print sample lines for /var/ossec/bin/wazuh-logtest
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List

import pandas as pd

from . import __version__
from .evaluate import DETECTORS, coverage_matrix, evaluate, label_windows, to_markdown
from .features import window_features
from .pipeline import Bundle, Split, device_map, score_windows, to_wazuh_alerts, train_bundle
from .simulate import (DEFAULT_START, incidents_frame, simulate, simulate_demo, to_json_line,
                       write_jsonl)
from .wazuh_io import normalize, write_ml_alerts

DEFAULT_BUNDLE = Path("models/bundle.joblib")


def _experiment(seed: int, target_fpr: float):
    events, incidents = simulate(seed=seed)
    frame = normalize(events)
    split = Split.by_days(DEFAULT_START)
    devices = device_map()
    windows, memory = window_features(frame, devices, split.start, split.end)
    bundle = train_bundle(windows, memory, split, devices, target_fpr=target_fpr, seed=seed)
    inc = incidents_frame(incidents)
    labelled = label_windows(score_windows(bundle, split.part(windows, "test")), inc)
    return events, inc, bundle, labelled, evaluate(labelled, inc)


def cmd_run(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("IoT SOC anomaly lab %s - offline experiment (seed %d)" % (__version__, args.seed))
    events, inc, bundle, labelled, results = _experiment(args.seed, args.target_fpr)
    print("Simulated %d gateway events from %d devices over 6 days; %d scripted incidents."
          % (len(events), len(bundle.devices), inc["incident_id"].nunique()))
    if args.write_events:
        write_jsonl(events, out / "gateway_events.jsonl")
    inc.to_csv(out / "incidents.csv", index=False)
    labelled.to_csv(out / "test_windows_scored.csv", index=False)
    results["summary"].to_csv(out / "summary.csv", index=False)
    results["coverage"].to_csv(out / "attack_coverage.csv", index=False)
    results["benign"].to_csv(out / "benign_flags.csv", index=False)
    alerts = to_wazuh_alerts(labelled, bundle.model_version)
    write_ml_alerts(alerts, out / "ml_alerts.json", append=False)

    summary = results["summary"]
    table = summary[["name", "precision", "recall", "pr_auc", "attacks_detected",
                     "median_minutes_to_detect", "false_incidents_per_day"]].copy()
    table["attacks_detected"] = table["attacks_detected"].astype(str) + "/" + \
        summary["attacks_total"].astype(str)
    pd.set_option("display.width", 200)
    print("\nTest day (24 h, 20 devices, 5-minute windows):")
    print(table.round(3).to_string(index=False))
    print("\nTime to detect each attack:")
    print(coverage_matrix(results["coverage"]).to_string())
    benign = results["benign"].pivot(index="scenario", columns="detector", values="devices_flagged")
    print("\nBenign-but-unusual events flagged (devices):")
    print(benign[[d for d in DETECTORS if d in benign.columns]].to_string())
    print("\nHybrid alerts by severity (triage):")
    print(results["triage"].round(1).to_string(index=False))

    multi = None
    if args.seeds > 1:
        rows = []
        for seed in range(args.seed, args.seed + args.seeds):
            print("  seed %d ..." % seed, flush=True)
            summary_s = _experiment(seed, args.target_fpr)[4]["summary"]
            rows.append(summary_s.assign(seed=seed))
        allseeds = pd.concat(rows, ignore_index=True)
        allseeds.to_csv(out / "summary_all_seeds.csv", index=False)
        metrics = ["precision", "recall", "pr_auc", "attacks_detected", "false_incidents_per_day"]
        multi = allseeds.groupby("detector", sort=False)[metrics].agg(["mean", "std", "min", "max"])
        multi = multi.reindex(DETECTORS)
        print("\nAcross %d seeds (mean, std, min, max):" % args.seeds)
        print(multi.round(3).to_string())

    _write_results_md(out, summary, results, multi, args)
    try:
        from .report import write_report
        path = write_report(out, labelled, inc, results, bundle, multi)
        print("\nReport: %s" % path)
    except ImportError:
        print("\n(matplotlib not installed - skipped report.html)")
    print("Outputs in %s/ . Anomaly scores are not attack probabilities." % out)
    return 0


def _ordered(table: pd.DataFrame) -> pd.DataFrame:
    return table[[d for d in DETECTORS if d in table.columns]]


def seed_table(multi: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for detector, row in multi.iterrows():
        cells = {"detector": detector}
        for metric in multi.columns.levels[0]:
            if metric not in multi.columns.get_level_values(0):
                continue
            m, sd, lo, hi = (row[(metric, k)] for k in ("mean", "std", "min", "max"))
            cells[metric] = "–" if pd.isna(m) else "%.2f ± %.2f (%.2f–%.2f)" % (m, sd, lo, hi)
        rows.append(cells)
    return pd.DataFrame(rows)


def _write_results_md(out: Path, summary: pd.DataFrame, results: Dict, multi, args) -> None:
    table = summary[["name", "precision", "recall", "f1", "pr_auc", "attacks_detected",
                     "median_minutes_to_detect", "incidents_per_day",
                     "false_incidents_per_day"]].rename(columns={"name": "detector"})
    parts = ["# Results (seed %d, target false-alarm rate %.3f)\n" % (args.seed, args.target_fpr),
             to_markdown(table), "\n## Minutes to first alert per attack\n",
             to_markdown(coverage_matrix(results["coverage"]).reset_index()),
             "\n## Benign-but-unusual events flagged (devices)\n",
             to_markdown(_ordered(results["benign"].pivot(index="scenario", columns="detector",
                                                          values="devices_flagged")).reset_index()),
             "\n## Hybrid alerts by severity\n", to_markdown(results["triage"], "%.1f")]
    if multi is not None:
        parts += ["\n## Across %d seeds: mean ± std (min–max)\n" % args.seeds,
                  to_markdown(seed_table(multi))]
    (out / "results.md").write_text("\n".join(parts) + "\n", encoding="utf-8")


def cmd_train(args) -> int:
    import joblib
    print("Simulating 5 clean days (1 warm-up, 3 train, 1 calibration) ...", flush=True)
    events, _ = simulate(days=5, seed=args.seed, attack_day=None)
    split = Split.by_days(DEFAULT_START, test=0)
    devices = device_map()
    windows, memory = window_features(normalize(events), devices, split.start, split.end)
    bundle = train_bundle(windows, memory, split, devices, target_fpr=args.target_fpr,
                          seed=args.seed)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    print("Saved %s (%s)" % (path, bundle.model_version))
    print(json.dumps({k: v for k, v in bundle.meta.items() if k != "features"}, indent=2,
                     default=str))
    return 0


def _load_bundle(path: Path) -> Bundle:
    import joblib
    if not Path(path).exists():
        sys.exit("Model bundle %s not found. Run: python -m iotsoc train --out %s" % (path, path))
    return joblib.load(path)


def cmd_replay(args) -> int:
    from .live import Console, demo_events, replay
    events, incidents = demo_events(args.minutes, args.speed, args.seed)
    console = Console()
    console.say("[replay]", "%d events, %g simulated minutes at %gx -> %s (about %.0f s)"
                % (len(events), args.minutes, args.speed, args.out,
                   args.minutes * 60 / args.speed))
    n = replay(events, incidents, Path(args.out), args.speed, console)
    console.say("[replay]", "done, %d events written" % n)
    return 0


def cmd_live(args) -> int:
    from .live import Console, run_scorer
    bundle = _load_bundle(Path(args.bundle))
    console = Console()
    console.say("[live]", "following %s -> ML alerts to %s (Ctrl+C to stop)"
                % (args.input, args.alerts_out))
    try:
        scorer = run_scorer(bundle, Path(args.input), Path(args.alerts_out), console,
                            from_start=args.from_start)
    except KeyboardInterrupt:
        return 0
    console.say("[live]", str(scorer.stats))
    return 0


def cmd_demo(args) -> int:
    from .live import Console, demo_events, replay, run_scorer
    bundle = _load_bundle(Path(args.bundle))
    console = Console()
    source = Path(args.archives) if args.source == "archives" else Path(args.gateway_log)
    events, incidents = demo_events(args.minutes, args.speed, args.seed)
    stop = threading.Event()
    stats: Dict = {}

    def scorer_thread():
        stats["scorer"] = run_scorer(bundle, source, Path(args.alerts_out), console,
                                     idle_flush=10.0, stop=stop)

    console.say("[demo]", "IoT SOC live demo: %d devices, %g simulated minutes at %gx speed (~%.0f s)"
                % (len(bundle.devices), args.minutes, args.speed, args.minutes * 60 / args.speed))
    console.say("[demo]", "gateway log -> %s | scorer reads %s | ML alerts -> %s"
                % (args.gateway_log, source, args.alerts_out))
    worker = threading.Thread(target=scorer_thread, daemon=True)
    worker.start()
    time.sleep(1.0)
    try:
        replay(events, incidents, Path(args.gateway_log), args.speed, console)
        console.say("[demo]", "replay finished; waiting for the last windows ...")
        time.sleep(args.drain)
    except KeyboardInterrupt:
        pass
    stop.set()
    worker.join(timeout=5)
    scorer = stats.get("scorer")
    if scorer is not None:
        stats = dict(scorer.stats)
        stats.setdefault("ml_alerts_sent", 0)
        stats.setdefault("suppressed_repeats", 0)
        console.say("[demo]", "scored %(windows)d device-windows from %(events)d events: "
                    "%(ml_alerts)d anomalous windows -> %(ml_alerts_sent)d alerts sent to Wazuh "
                    "(%(suppressed_repeats)d repeats suppressed, %(late)d late events)" % stats)
    console.say("[demo]", "In the Wazuh dashboard filter on: rule.groups:iotsoc")
    return 0


def cmd_samples(args) -> int:
    events, incidents = simulate_demo(DEFAULT_START, minutes=120, seed=args.seed)
    wanted = {}
    for event in events:
        key = (event["kind"], event.get("outcome"), event.get("fw_signed"),
               event.get("topic") if event.get("topic") in ("#", "$SYS/#") else None,
               event.get("allowlisted"))
        wanted.setdefault(key, event)
    for event in wanted.values():
        print(to_json_line(event))
    print(json.dumps({"iotsoc": "ml", "detector": "ensemble-2of3", "model_version": "sample",
                      "device_id": "cam-04", "device_type": "camera",
                      "window_start": "2026-09-19T15:15:00Z", "window_end": "2026-09-19T15:20:00Z",
                      "severity": "high", "votes": 3, "voters": "iforest,lof,autoencoder",
                      "score": 2.4, "signature_overlap": "none",
                      "reasons": "bytes sent to the internet 29.9 MB (usual 0 B-39.5 kB)"},
                     separators=(",", ":")))
    return 0


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m iotsoc", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="offline experiment with evaluation and report")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--seeds", type=int, default=1, help="repeat with N seeds and report mean/std")
    p.add_argument("--target-fpr", type=float, default=0.002)
    p.add_argument("--out", default="output")
    p.add_argument("--write-events", action="store_true", help="also save the raw events (~30 MB)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("train", help="train the bundle for live scoring")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--target-fpr", type=float, default=0.002)
    p.add_argument("--out", default=str(DEFAULT_BUNDLE))
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("replay", help="append the demo stream to a gateway log")
    p.add_argument("--out", default="/var/log/iotsoc/gateway.json")
    p.add_argument("--minutes", type=float, default=120)
    p.add_argument("--speed", type=float, default=40)
    p.add_argument("--seed", type=int, default=11)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("live", help="score a growing archives.json / gateway log")
    p.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    p.add_argument("--input", default="/var/ossec/logs/archives/archives.json")
    p.add_argument("--alerts-out", default="/var/log/iotsoc/ml_alerts.json")
    p.add_argument("--from-start", action="store_true")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("demo", help="replay + live scoring for the workshop")
    p.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    p.add_argument("--gateway-log", default="/var/log/iotsoc/gateway.json")
    p.add_argument("--archives", default="/var/ossec/logs/archives/archives.json")
    p.add_argument("--source", choices=["archives", "gateway"], default="archives",
                   help="score what Wazuh forwards (archives) or read the gateway log directly")
    p.add_argument("--alerts-out", default="/var/log/iotsoc/ml_alerts.json")
    p.add_argument("--minutes", type=float, default=120)
    p.add_argument("--speed", type=float, default=40)
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("--drain", type=float, default=20.0, help="seconds to wait after replay")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("samples", help="sample lines for wazuh-logtest")
    p.add_argument("--seed", type=int, default=11)
    p.set_defaults(func=cmd_samples)

    args = parser.parse_args(argv)
    return args.func(args)
