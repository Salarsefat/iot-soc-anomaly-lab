"""Turn gateway events into per-device 5-minute behaviour windows.

The same functions are used for batch experiments and for the live Wazuh
scorer, so training and serving compute features identically.

Two ideas matter more than the choice of anomaly algorithm:
  * behaviour over time: counts, volumes and novelty per device per window,
    plus 1-hour rolling sums so low-and-slow activity accumulates;
  * self-baselines: each feature is compared with the same device's own
    history at the same time of day (business hours vs night).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from .fleet import BUSINESS_HOURS

WINDOW = pd.Timedelta("5min")
ROLL_WINDOWS = 12                     # 12 x 5 min = 1 hour
NOVELTY_HORIZON = pd.Timedelta("24h")  # "new" = not contacted by this device in 24 h
HIGH_ENTROPY_BITS = 3.3

BASE_FEATURES = [
    "mqtt_pub", "mqtt_bytes", "mqtt_conn_ok", "mqtt_conn_fail", "mqtt_sub",
    "auth_ok", "auth_fail", "int_flows", "ext_flows", "int_bytes_out", "ext_bytes_out",
    "bytes_in", "uniq_dst", "uniq_dst_port", "new_dst", "dns_q", "new_domains",
    "dns_high_entropy", "fw_updates", "config_changes",
]
ROLLING = {"auth_fail_1h": "auth_fail", "ext_flows_1h": "ext_flows", "new_dst_1h": "new_dst"}
# Signature-style fields: used by the rules, deliberately NOT given to the ML models.
RULE_FEATURES = ["wildcard_sub", "fw_unsigned", "int_unexpected"]
ML_FEATURES = BASE_FEATURES + list(ROLLING)
ALL_COUNTS = BASE_FEATURES + RULE_FEATURES
SUMMED = [f for f in ALL_COUNTS if f not in ("uniq_dst", "uniq_dst_port")]

FEATURE_LABELS = {
    "mqtt_pub": "MQTT messages published", "mqtt_bytes": "MQTT bytes published",
    "mqtt_conn_ok": "MQTT connections", "mqtt_conn_fail": "failed MQTT connections",
    "mqtt_sub": "MQTT subscriptions", "auth_ok": "successful device logins",
    "auth_fail": "failed device logins", "auth_fail_1h": "failed logins in the last hour",
    "int_flows": "internal connections", "ext_flows": "internet connections",
    "ext_flows_1h": "internet connections in the last hour",
    "int_bytes_out": "bytes sent internally", "ext_bytes_out": "bytes sent to the internet",
    "bytes_in": "bytes received", "uniq_dst": "distinct destinations",
    "uniq_dst_port": "distinct destination ports", "new_dst": "never-seen destinations",
    "new_dst_1h": "never-seen destinations in the last hour", "dns_q": "DNS lookups",
    "new_domains": "never-seen domains", "dns_high_entropy": "random-looking domains",
    "fw_updates": "firmware updates", "config_changes": "configuration changes",
}
BYTE_FEATURES = {"mqtt_bytes", "int_bytes_out", "ext_bytes_out", "bytes_in"}

Memory = Dict[Tuple[str, str, str], pd.Timestamp]   # (kind, device, value) -> last seen


def label_entropy(qname: Optional[str]) -> float:
    """Shannon entropy (bits per character) of the left-most DNS label."""
    if not qname:
        return 0.0
    label = str(qname).split(".")[0]
    if not label:
        return 0.0
    counts = Counter(label)
    n = len(label)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def period_of(window_start: pd.Series) -> pd.Series:
    hours = window_start.dt.hour
    return pd.Series(np.where((hours >= BUSINESS_HOURS[0]) & (hours < BUSINESS_HOURS[1]),
                              "day", "night"), index=window_start.index)


def _mark_novel(events: pd.DataFrame, mask: pd.Series, column: str, kind: str,
                memory: Memory, horizon: pd.Timedelta) -> pd.Series:
    flags = pd.Series(False, index=events.index)
    sub = events.loc[mask, ["ts", "device_id", column]]
    if sub.empty:
        return flags
    previous = sub.groupby(["device_id", column], sort=False)["ts"].shift()
    first = previous.isna()
    if first.any() and memory:
        remembered = [memory.get((kind, d, str(v))) for d, v in
                      zip(sub.loc[first, "device_id"], sub.loc[first, column])]
        previous.loc[first] = pd.to_datetime(pd.Series(remembered, index=previous.index[first]),
                                             utc=True).astype(previous.dtype)
    is_new = previous.isna() | ((sub["ts"] - previous) > horizon)
    flags.loc[sub.index] = is_new.to_numpy()
    last = sub.groupby(["device_id", column])["ts"].max()
    for (device, value), ts in last.items():
        memory[(kind, device, str(value))] = ts
    return flags


def mark_novelty(events: pd.DataFrame, memory: Optional[Memory] = None,
                 horizon: pd.Timedelta = NOVELTY_HORIZON) -> Tuple[pd.DataFrame, Memory]:
    """Flag the first contact of a destination / domain in `horizon` per device.

    `events` must be sorted by time. `memory` carries last-seen times between
    calls (live scoring) and is updated in place and returned.
    """
    memory = {} if memory is None else memory
    events = events.copy()
    flows = events["kind"].eq("flow") & events["dst_ip"].notna()
    dns = events["kind"].eq("dns_query") & events["qname"].notna()
    events["is_new_dst"] = _mark_novel(events, flows, "dst_ip", "dst", memory, horizon)
    events["is_new_domain"] = _mark_novel(events, dns, "qname", "dns", memory, horizon)
    return events, memory


def _event_columns(ev: pd.DataFrame) -> pd.DataFrame:
    kind = ev["kind"]
    outcome = ev["outcome"]
    flow = kind.eq("flow")
    internal = flow & ev["dst_zone"].eq("internal")
    external = flow & ev["dst_zone"].eq("external")
    pub = kind.eq("mqtt_publish")
    sub = kind.eq("mqtt_subscribe")
    topic = ev["topic"].fillna("").astype(str)
    dns = kind.eq("dns_query")
    fw = kind.eq("fw_update")
    bytes_out = ev["bytes_out"].fillna(0.0)
    cols = pd.DataFrame({
        "device_id": ev["device_id"], "window_start": ev["ts"].dt.floor(WINDOW),
        "mqtt_pub": pub, "mqtt_bytes": ev["bytes"].fillna(0.0).where(pub, 0.0),
        "mqtt_conn_ok": kind.eq("mqtt_connect") & outcome.eq("success"),
        "mqtt_conn_fail": kind.eq("mqtt_connect") & outcome.eq("failure"),
        "mqtt_sub": sub,
        "wildcard_sub": sub & (topic.eq("#") | topic.str.startswith("$SYS")),
        "auth_ok": kind.eq("device_auth") & outcome.eq("success"),
        "auth_fail": kind.eq("device_auth") & outcome.eq("failure"),
        "int_flows": internal, "ext_flows": external,
        "int_bytes_out": bytes_out.where(internal, 0.0),
        "ext_bytes_out": bytes_out.where(external, 0.0),
        "bytes_in": ev["bytes_in"].fillna(0.0).where(flow | fw, 0.0),
        "int_unexpected": internal & ev["allowlisted"].eq("no"),
        "flow_dst": ev["dst_ip"].where(flow), "flow_port": ev["dst_port"].where(flow),
        "new_dst": ev["is_new_dst"] & flow,
        "dns_q": dns, "new_domains": ev["is_new_domain"] & dns,
        "dns_high_entropy": dns & (ev["qname"].map(label_entropy) >= HIGH_ENTROPY_BITS),
        "fw_updates": fw, "fw_unsigned": fw & ev["fw_signed"].astype(str).str.lower().eq("false"),
        "config_changes": kind.eq("config_change"),
    })
    return cols


def add_rolling(windows: pd.DataFrame, history: Optional[pd.DataFrame] = None) -> pd.DataFrame:
    """Add 1-hour rolling sums. `history` = earlier windows of the same devices."""
    base = windows
    if history is not None and len(history):
        base = pd.concat([history[["device_id", "window_start"] + list(ROLLING.values())],
                          windows], ignore_index=True)
    base = base.sort_values(["device_id", "window_start"], kind="stable")
    for name, source in ROLLING.items():
        rolled = (base.groupby("device_id", sort=False)[source]
                  .rolling(ROLL_WINDOWS, min_periods=1).sum()
                  .reset_index(level=0, drop=True))
        base[name] = rolled
    keys = windows.set_index(["device_id", "window_start"]).index
    out = base.set_index(["device_id", "window_start"]).loc[keys, list(ROLLING)].to_numpy()
    windows = windows.copy()
    windows[list(ROLLING)] = out
    return windows


def window_features(events: pd.DataFrame, devices: Dict[str, str], start: pd.Timestamp,
                    end: pd.Timestamp, memory: Optional[Memory] = None,
                    history: Optional[pd.DataFrame] = None) -> Tuple[pd.DataFrame, Memory]:
    """Aggregate events into a full device x 5-minute grid on [start, end).

    devices: device_id -> device_type for every device that should get a row
    in every window (idle windows are zero-filled rows, not missing rows).
    """
    start, end = pd.Timestamp(start), pd.Timestamp(end)
    if start != start.floor(WINDOW) or end != end.floor(WINDOW) or start >= end:
        raise ValueError("start/end must be 5-minute aligned with start < end")
    scoped = events[(events["ts"] >= start) & (events["ts"] < end)
                    & events["device_id"].isin(list(devices))]
    scoped, memory = mark_novelty(scoped, memory)
    cols = _event_columns(scoped)
    grouped = cols.groupby(["device_id", "window_start"])
    agg = grouped[SUMMED].sum()
    agg["uniq_dst"] = grouped["flow_dst"].nunique()
    agg["uniq_dst_port"] = grouped["flow_port"].nunique()
    grid = pd.MultiIndex.from_product(
        [sorted(devices), pd.date_range(start, end, freq=WINDOW, inclusive="left")],
        names=["device_id", "window_start"])
    windows = agg.reindex(grid, fill_value=0).astype(float).reset_index()
    windows["device_type"] = windows["device_id"].map(devices)
    windows["period"] = period_of(windows["window_start"])
    windows = add_rolling(windows, history)
    ordered = ["device_id", "device_type", "window_start", "period"] + ML_FEATURES + RULE_FEATURES
    return windows[ordered].sort_values(["window_start", "device_id"]).reset_index(drop=True), memory


class DeviceBaseline:
    """Robust per-device, per-period baseline on log1p(x).

    Inside the device's normal range: z = (log1p(x) - median) / scale with
    scale = max(1.4826 * MAD, tail spread, floor). Beyond the range, distance
    grows by one unit per `floor` log-units. The floor stops a feature that is
    always zero in training from turning a single event into an infinite z.
    Unknown devices fall back to the baseline of their device type.
    """

    def __init__(self, features: Sequence[str] = tuple(ML_FEATURES), floor: float = 0.5,
                 clip: float = 25.0):
        self.features = list(features)
        self.floor = floor
        self.clip = clip

    @staticmethod
    def _keys(windows: pd.DataFrame, column: str) -> pd.Series:
        return windows[column].astype(str) + "|" + windows["period"].astype(str)

    def fit(self, windows: pd.DataFrame) -> "DeviceBaseline":
        g = np.log1p(windows[self.features].astype(float))
        self.stats = {}
        for column in ("device_id", "device_type"):
            keys = self._keys(windows, column)
            grouped = g.groupby(keys)
            median = grouped.median()
            mad = (g - median.loc[keys].to_numpy()).abs().groupby(keys).median()
            # Many IoT features are zero-inflated (a message every 10 min, a cloud sync
            # every 15 min), so MAD is often 0. The tail spread keeps rare-but-normal
            # values from looking extreme: sigma ~ (q99 - median) / 2.326 for a normal.
            hi = grouped.quantile(0.99)
            lo = grouped.quantile(0.01)
            upper = (hi - median) / 2.326
            lower = (median - lo) / 2.326
            scale = np.maximum(np.maximum(1.4826 * mad, np.maximum(upper, lower)), self.floor)
            raw = windows[self.features].astype(float).groupby(keys)
            self.stats[column] = (median, scale, raw.median(), lo, hi,
                                  raw.quantile(0.01), raw.quantile(0.99))
        return self

    def _lookup(self, windows: pd.DataFrame, which: int) -> pd.DataFrame:
        by_device = self.stats["device_id"][which]
        by_type = self.stats["device_type"][which]
        dkeys = self._keys(windows, "device_id")
        tkeys = self._keys(windows, "device_type")
        known = dkeys.isin(by_device.index)
        out = pd.DataFrame(index=windows.index, columns=self.features, dtype=float)
        if known.any():
            out.loc[known] = by_device.loc[dkeys[known]].to_numpy()
        if (~known).any():
            if not tkeys[~known].isin(by_type.index).all():
                raise ValueError("No baseline for some device types: %s"
                                 % sorted(set(tkeys[~known]) - set(by_type.index)))
            out.loc[~known] = by_type.loc[tkeys[~known]].to_numpy()
        return out

    def transform(self, windows: pd.DataFrame) -> pd.DataFrame:
        """Inside the normal range [q01, q99]: robust z. Beyond it, every `floor`
        log-units (x1.65) adds one more unit, so a 1000x jump in a usually-zero
        byte counter is extreme while an ordinary non-zero value is not."""
        g = np.log1p(windows[self.features].astype(float))
        median, scale = self._lookup(windows, 0), self._lookup(windows, 1)
        lo, hi = self._lookup(windows, 3), self._lookup(windows, 4)
        core = (g - median) / scale
        above = (hi - median) / scale + (g - hi) / self.floor
        below = (lo - median) / scale + (g - lo) / self.floor
        z = core.where(g <= hi, above).where(g >= lo, below)
        return z.clip(-self.clip, self.clip)

    def usual(self, windows: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Typical raw range (1st-99th percentile) for each window's device and period."""
        return self._lookup(windows, 5), self._lookup(windows, 6)


def humanize(feature: str, value: float) -> str:
    if feature in BYTE_FEATURES:
        for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
            if abs(value) >= size:
                return "%.1f %s" % (value / size, unit)
        return "%d B" % round(value)
    return "%g" % round(value, 1)


def _usual_text(feature: str, lo: float, hi: float) -> str:
    if humanize(feature, lo) == humanize(feature, hi):
        return humanize(feature, lo)
    return "%s-%s" % (humanize(feature, lo), humanize(feature, hi))


def explain(windows: pd.DataFrame, z: pd.DataFrame, usual: Tuple[pd.DataFrame, pd.DataFrame],
            top: int = 3, min_abs_z: float = 2.5) -> List[str]:
    """One short analyst-readable reason string per window."""
    reasons: List[str] = []
    low, high = usual
    for i in range(len(windows)):
        row = z.iloc[i]
        order = row.abs().sort_values(ascending=False)

        def describe(feature: str) -> str:
            return "%s %s (usual %s)" % (
                FEATURE_LABELS.get(feature, feature),
                humanize(feature, float(windows.iloc[i][feature])),
                _usual_text(feature, float(low.iloc[i][feature]), float(high.iloc[i][feature])))

        strong = [f for f in order.index[:top] if abs(row[f]) >= min_abs_z]
        if strong:
            reasons.append("; ".join(describe(f) for f in strong))
            continue
        # No single feature is far off: name the largest small deviations, so the
        # analyst can still see what changed (often a benign reconnect or restart).
        weak = [f for f in order.index[:2] if abs(row[f]) >= 0.5]
        reasons.append("small deviations only: " + "; ".join(describe(f) for f in weak)
                       if weak else "combination of small deviations")
    return reasons
