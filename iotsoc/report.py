"""Self-contained HTML report (tables + figures embedded as PNG)."""
from __future__ import annotations

import base64
import html
import io
from pathlib import Path
from typing import Dict, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .evaluate import DETECTORS, DISPLAY, coverage_matrix  # noqa: E402
from .features import WINDOW  # noqa: E402

PAGE_BG, TEXT, TEXT_SOFT, SPINE, GRID = "#eefafd", "#0f232c", "#425961", "#a4b9c0", "#d7e2e6"
SCORE, ALERT, RULE_HIT, ATTACK, BENIGN = "#6e4eaa", "#a5981c", "#5e1709", "#d666c2", "#509f95"
DETECTOR_COLORS = dict(zip(DETECTORS, ["#2b949a", "#a2823e", "#2258c0", "#7e2567", "#a4401c",
                                       "#9865d9", "#476c2e"]))


def _png(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight", facecolor=PAGE_BG)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _style(ax) -> None:
    ax.set_facecolor(PAGE_BG)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(SPINE)
    ax.tick_params(colors=TEXT_SOFT, labelsize=8)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def fig_detectors(summary: pd.DataFrame) -> str:
    names = [DISPLAY[d] for d in summary["detector"]][::-1]
    colors = [DETECTOR_COLORS.get(d, TEXT_SOFT) for d in summary["detector"]][::-1]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.4), sharey=True)
    for ax, column, title, fmt in (
            (axes[0], "attacks_detected", "Attacks detected (of %d)" % summary["attacks_total"].iloc[0], "%d"),
            (axes[1], "false_incidents_per_day", "False-alarm incidents per day", "%.0f")):
        values = summary[column].to_numpy()[::-1]
        ax.barh(names, values, color=colors, height=0.55)
        for y, v in enumerate(values):
            ax.text(v, y, "  " + fmt % v, va="center", fontsize=8, color=TEXT)
        ax.set_title(title, fontsize=10, color=TEXT, loc="left")
        _style(ax)
    axes[0].tick_params(axis="y", labelsize=8, colors=TEXT)
    fig.tight_layout()
    return _png(fig)


def fig_timelines(labelled: pd.DataFrame, incidents: pd.DataFrame) -> str:
    attacks = incidents[incidents["category"] == "attack"]
    devices = list(dict.fromkeys(attacks["device_id"])) + ["cam-01"]
    fig, axes = plt.subplots(len(devices), 1, figsize=(10, 1.25 * len(devices)), sharex=True)
    for ax, device in zip(np.atleast_1d(axes), devices):
        rows = labelled[labelled["device_id"] == device].sort_values("window_start")
        x = rows["window_start"].dt.tz_convert(None)
        for _, inc in incidents[incidents["device_id"] == device].iterrows():
            color = ATTACK if inc["category"] == "attack" else BENIGN
            ax.axvspan(inc["start"].tz_convert(None), inc["end"].tz_convert(None),
                       color=color, alpha=0.18, linewidth=0)
            y = 1.02 if inc["category"] == "attack" else 0.04
            ax.text(inc["start"].tz_convert(None), y, inc["scenario"].replace("_", " "),
                    transform=ax.get_xaxis_transform(), fontsize=7, color=TEXT_SOFT,
                    ha="left" if inc["category"] == "attack" else "right")
        ax.plot(x, rows["score_ml"], color=SCORE, linewidth=1.2)
        ax.axhline(0, color=SPINE, linewidth=0.8, linestyle="--")
        ml = rows["alert_ml"].to_numpy()
        ax.scatter(x[ml], rows["score_ml"][ml], s=14, color=ALERT, zorder=3,
                   edgecolor=PAGE_BG, linewidth=0.6)
        rule = rows["alert_rules"].to_numpy()
        ax.scatter(x[rule], np.full(rule.sum(), rows["score_ml"].max()), marker="v",
                   s=22, color=RULE_HIT, zorder=4)
        ax.set_ylabel(device, rotation=0, ha="right", va="center", fontsize=8, color=TEXT)
        _style(ax)
        ax.grid(False)
    handles = [plt.Line2D([], [], color=SCORE, linewidth=1.2, label="ML score (log of score / threshold)"),
               plt.Line2D([], [], marker="o", linestyle="", color=ALERT, label="ML alert"),
               plt.Line2D([], [], marker="v", linestyle="", color=RULE_HIT, label="signature rule hit"),
               plt.Rectangle((0, 0), 1, 1, color=ATTACK, alpha=0.25, label="attack"),
               plt.Rectangle((0, 0), 1, 1, color=BENIGN, alpha=0.3, label="benign but unusual")]
    fig.legend(handles=handles, loc="upper center", ncol=5, fontsize=8, frameon=False,
               bbox_to_anchor=(0.5, 1.01), labelcolor=TEXT)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    return _png(fig)


def _table(frame: pd.DataFrame, floatfmt: str = "{:.3f}") -> str:
    def fmt(v):
        if isinstance(v, float):
            return "–" if np.isnan(v) else floatfmt.format(v)
        return html.escape(str(v))
    head = "".join("<th>%s</th>" % html.escape(str(c)) for c in frame.columns)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % fmt(v) for v in row)
                   for row in frame.itertuples(index=False))
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (head, body)


CSS = """
body{font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#eefafd;color:#0f232c}
main{max-width:1060px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
p.sub{color:#425961;margin:0 0 16px}
.wrap{overflow-x:auto}table{border-collapse:collapse;font-size:13px;margin:8px 0;min-width:520px}
th,td{padding:6px 10px;border-bottom:1px solid #cfe1e8;text-align:left;white-space:nowrap}
th{color:#425961;font-weight:600}img{max-width:100%;height:auto}
.note{background:#e0f3fb;border-radius:8px;padding:12px 16px;color:#2b373a}
"""


def write_report(out: Path, labelled: pd.DataFrame, incidents: pd.DataFrame, results: Dict,
                 bundle, multi: Optional[pd.DataFrame] = None) -> Path:
    summary = results["summary"]
    view = summary[["name", "precision", "recall", "pr_auc", "attacks_detected",
                    "median_minutes_to_detect", "false_incidents_per_day"]].rename(columns={
                        "name": "Detector", "pr_auc": "PR-AUC", "attacks_detected": "Attacks found",
                        "median_minutes_to_detect": "Median min to detect",
                        "false_incidents_per_day": "False incidents / day"})
    view = view.assign(**{
        "Attacks found": summary["attacks_detected"].astype(str) + " / " + summary["attacks_total"].astype(str),
        "Median min to detect": summary["median_minutes_to_detect"].map(
            lambda v: "–" if pd.isna(v) else "%.0f" % v),
        "False incidents / day": summary["false_incidents_per_day"].map("{:.1f}".format)})
    coverage = coverage_matrix(results["coverage"]).rename(columns=DISPLAY).reset_index()
    benign = results["benign"].pivot(index="scenario", columns="detector",
                                     values="devices_flagged")
    benign = benign[[d for d in DETECTORS if d in benign.columns]].rename(columns=DISPLAY).reset_index()
    attacks = incidents[incidents["category"] == "attack"].drop_duplicates("incident_id")
    scen = attacks[["scenario", "device_id", "start", "end", "mitre", "signature_rule"]].copy()
    scen["start"] = scen["start"].dt.strftime("%H:%M")
    scen["end"] = scen["end"].dt.strftime("%H:%M")
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>IoT SOC Results</title><style>%s</style></head><body><main>" % CSS,
        "<h1>IoT SOC anomaly lab - results</h1>",
        "<p class='sub'>Simulated smart-building gateway, %d devices, 5-minute windows. "
        "Trained on 3 normal days, thresholds set on 1 normal day (target false-alarm rate "
        "%.3f per window), tested on 1 day with 7 attacks and 3 benign surprises. "
        "Model %s.</p>" % (len(bundle.devices), bundle.suite.target_fpr, html.escape(bundle.model_version)),
        "<h2>Detectors on the test day</h2><div class='wrap'>%s</div>" % _table(view),
        "<img alt='Attacks detected and false-alarm incidents per detector' src='data:image/png;base64,%s'>"
        % fig_detectors(summary),
        "<h2>Minutes from attack start to first alert</h2><div class='wrap'>%s</div>" % _table(coverage),
        "<h2>Benign-but-unusual events that raised alerts (devices)</h2><div class='wrap'>%s</div>"
        % _table(benign, "{:.0f}"),
        "<h2>Hybrid alerts by severity (triage)</h2><div class='wrap'>%s</div>"
        % _table(results["triage"], "{:.1f}"),
        "<h2>Attack scenarios (test day, UTC)</h2><div class='wrap'>%s</div>" % _table(scen),
        "<h2>ML score per attacked device (above 0 = above threshold)</h2>",
        "<img alt='Ensemble anomaly score over the test day for each attacked device' "
        "src='data:image/png;base64,%s'>" % fig_timelines(labelled, incidents),
    ]
    if multi is not None:
        from .cli import seed_table
        parts.append("<h2>Stability across seeds: mean ± std (min–max)</h2><div class='wrap'>%s</div>"
                     % _table(seed_table(multi).rename(columns={"detector": "Detector"})))
    parts.append(
        "<h2>How to read this</h2><div class='note'><p>Window metrics count every 5-minute "
        "device window; an alert in the hour after an attack ends counts as a false positive "
        "there, but not as a false incident. Incidents merge consecutive alerted windows of one "
        "device. The calibration target is not a guarantee: it was estimated from a single "
        "normal day. Synthetic data shows the workflow and trade-offs; it does not prove "
        "production performance.</p></div></main></body></html>")
    path = Path(out) / "report.html"
    path.write_text("\n".join(parts), encoding="utf-8")
    return path
