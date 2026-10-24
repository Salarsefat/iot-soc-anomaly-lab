"""SOC-oriented evaluation: windows, incidents, alert volume and time to detect."""
from __future__ import annotations

from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from .features import WINDOW

TAIL = pd.Timedelta("1h")

DETECTORS = ["rules", "iforest_raw", "iforest", "lof", "autoencoder", "ensemble", "hybrid"]
SEVERITIES = ["high", "medium"]
DISPLAY = {
    "rules": "Signature rules (Wazuh-style)",
    "iforest_raw": "Isolation Forest, raw features",
    "iforest": "Isolation Forest + device baselines",
    "lof": "LOF + device baselines",
    "autoencoder": "Autoencoder + device baselines",
    "ensemble": "Ensemble (2 of 3 agree)",
    "hybrid": "Hybrid: rules OR ML policy",
}


def label_windows(scored: pd.DataFrame, incidents: pd.DataFrame) -> pd.DataFrame:
    """Attach ground truth after scoring. A window is positive if it overlaps an attack."""
    out = scored.copy()
    out["attack"] = 0
    out["attack_scenario"] = ""
    out["benign_scenario"] = ""
    out["after_incident"] = 0   # within 1 h after an incident ends (rolling features still elevated)
    w0 = out["window_start"]
    w1 = w0 + WINDOW
    for _, inc in incidents.iterrows():
        mask = (out["device_id"] == inc["device_id"]) & (w0 < inc["end"]) & (w1 > inc["start"])
        tail = ((out["device_id"] == inc["device_id"]) & (w0 >= inc["end"])
                & (w0 < inc["end"] + TAIL))
        out.loc[tail, "after_incident"] = 1
        if inc["category"] == "attack":
            out.loc[mask, "attack"] = 1
            out.loc[mask, "attack_scenario"] = inc["scenario"]
        else:
            out.loc[mask & (out["attack"] == 0), "benign_scenario"] = inc["scenario"]
    return out


def merge_incidents(flags: pd.DataFrame) -> pd.DataFrame:
    """Merge consecutive alerted windows of one device into analyst-facing incidents."""
    rows = []
    for device, group in flags.sort_values("window_start").groupby("device_id"):
        starts = group["window_start"].tolist()
        begin = prev = starts[0]
        for ws in starts[1:] + [None]:
            if ws is not None and ws - prev <= WINDOW:
                prev = ws
                continue
            rows.append({"device_id": device, "start": begin, "end": prev + WINDOW})
            if ws is not None:
                begin = prev = ws
    return pd.DataFrame(rows, columns=["device_id", "start", "end"])


def evaluate(labelled: pd.DataFrame, incidents: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    days = max(1e-9, (labelled["window_start"].max() + WINDOW
                      - labelled["window_start"].min()) / pd.Timedelta("1D"))
    attacks = incidents[incidents["category"] == "attack"]
    benign = incidents[incidents["category"] == "benign"]
    truth = labelled["attack"].to_numpy()
    summary, coverage, benign_rows = [], [], []
    for name in DETECTORS:
        flag = labelled["alert_" + name].to_numpy(dtype=bool)
        precision, recall, f1, _ = precision_recall_fscore_support(
            truth, flag, average="binary", zero_division=0)
        score_col = "score_" + name
        ap = (average_precision_score(truth, labelled[score_col])
              if score_col in labelled and truth.any() else np.nan)
        alerted = labelled[flag]
        all_incidents = merge_incidents(alerted) if len(alerted) else pd.DataFrame(
            columns=["device_id", "start", "end"])
        clean = labelled[flag & (labelled["attack"] == 0) & (labelled["benign_scenario"] == "")
                         & (labelled["after_incident"] == 0)]
        fp_incidents = merge_incidents(clean) if len(clean) else clean
        detected, delays = 0, []
        for _, inc in attacks.iterrows():
            hit = alerted[(alerted["device_id"] == inc["device_id"])
                          & (alerted["window_start"] < inc["end"] + WINDOW)
                          & (alerted["window_start"] + WINDOW > inc["start"])]
            delay = np.nan
            if len(hit):
                detected += 1
                delay = (hit["window_start"].min() + WINDOW - inc["start"]) / pd.Timedelta("1min")
                delays.append(delay)
            coverage.append({"detector": name, "incident_id": inc["incident_id"],
                             "scenario": inc["scenario"], "device_id": inc["device_id"],
                             "detected": bool(len(hit)), "minutes_to_detect": delay})
        for scenario, group in benign.groupby("scenario"):
            flagged = 0
            for _, inc in group.iterrows():
                flagged += int(((alerted["device_id"] == inc["device_id"])
                                & (alerted["window_start"] < inc["end"])
                                & (alerted["window_start"] + WINDOW > inc["start"])).any())
            benign_rows.append({"detector": name, "scenario": scenario,
                                "devices_flagged": flagged, "devices": len(group)})
        summary.append({
            "detector": name, "name": DISPLAY[name],
            "precision": precision, "recall": recall, "f1": f1, "pr_auc": ap,
            "attacks_detected": detected, "attacks_total": len(attacks),
            "median_minutes_to_detect": float(np.median(delays)) if delays else np.nan,
            "alert_windows": int(flag.sum()),
            "incidents_per_day": len(all_incidents) / days,
            "false_incidents_per_day": len(fp_incidents) / days,
        })
    triage = []
    for severity in SEVERITIES:
        flagged = labelled[labelled["alert_hybrid"] & (labelled["severity"] == severity)]
        clean = flagged[(flagged["attack"] == 0) & (flagged["benign_scenario"] == "")
                        & (flagged["after_incident"] == 0)]
        triage.append({"severity": severity, "alert_windows": len(flagged),
                       "attack_windows": int(flagged["attack"].sum()),
                       "benign_event_windows": int((flagged["benign_scenario"] != "").sum()),
                       "false_incidents_per_day": (len(merge_incidents(clean)) if len(clean)
                                                   else 0) / days})
    rules_only = labelled[labelled["alert_rules"] & ~labelled["alert_ml"]]
    triage.append({"severity": "rule only", "alert_windows": len(rules_only),
                   "attack_windows": int(rules_only["attack"].sum()),
                   "benign_event_windows": int((rules_only["benign_scenario"] != "").sum()),
                   "false_incidents_per_day": np.nan})
    return {"summary": pd.DataFrame(summary), "coverage": pd.DataFrame(coverage),
            "benign": pd.DataFrame(benign_rows), "triage": pd.DataFrame(triage)}


def coverage_matrix(coverage: pd.DataFrame) -> pd.DataFrame:
    def cell(row) -> str:
        return "%.0f min" % row["minutes_to_detect"] if row["detected"] else "missed"
    table = coverage.assign(cell=coverage.apply(cell, axis=1)).pivot(
        index="scenario", columns="detector", values="cell")
    order = [d for d in DETECTORS if d in table.columns]
    return table[order]


def to_markdown(frame: pd.DataFrame, floatfmt: str = "%.3f") -> str:
    cols = [str(c) for c in frame.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, row in frame.iterrows():
        cells: List[str] = []
        for value in row:
            if isinstance(value, float):
                cells.append("–" if np.isnan(value) else floatfmt % value)
            else:
                cells.append(str(value))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
