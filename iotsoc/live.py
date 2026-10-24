"""Live mode: replay gateway events into Wazuh and score what Wazuh forwards.

    replay  -> /var/log/iotsoc/gateway.json     (Wazuh logcollector reads it)
    Wazuh   -> /var/ossec/logs/archives/archives.json   (logall_json=yes)
    scorer  -> follows archives.json, closes 5-minute windows, scores them
            -> /var/log/iotsoc/ml_alerts.json   (Wazuh reads it, rules 10062x fire)

The scorer uses exactly the same feature and scoring functions as the batch
experiment (see tests/test_live_matches_batch.py).
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

import pandas as pd

from .features import ROLL_WINDOWS, ROLLING, WINDOW, window_features
from .pipeline import Bundle, score_windows, to_wazuh_alerts
from .simulate import SCENARIOS, Incident, iso, simulate_demo, to_json_line
from .wazuh_io import normalize, parse_line, write_ml_alerts


def _ts(value) -> pd.Timestamp:
    if isinstance(value, (int, float)):
        return pd.Timestamp(float(value), unit="s", tz="UTC")
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


class LiveScorer:
    """Incremental, event-time windowing with a watermark.

    A window [w, w+5min) is closed once an event later than w+5min+lateness has
    been seen (or on flush). Events older than the oldest open window are
    counted as late and dropped.
    """

    # Wazuh's analysis threads can reorder events by about a second of real time;
    # at 40x replay speed that is ~40 s of simulated time, so wait 2 minutes.
    def __init__(self, bundle: Bundle, lateness: pd.Timedelta = pd.Timedelta("120s")):
        self.bundle = bundle
        self.lateness = lateness
        self.memory: Optional[dict] = None
        self.history: Optional[pd.DataFrame] = None
        self.next_window: Optional[pd.Timestamp] = None
        self.buffer: List[Tuple[pd.Timestamp, Dict]] = []
        self.max_ts: Optional[pd.Timestamp] = None
        self.stats = {"events": 0, "late": 0, "windows": 0, "ml_alerts": 0}

    def add(self, event: Dict) -> List[pd.DataFrame]:
        ts = _ts(event["ts"])
        if self.next_window is None:
            self.next_window = ts.floor(WINDOW)
            self.memory, self.history = self.bundle.rebased(self.next_window)
        if ts < self.next_window:
            self.stats["late"] += 1
            return []
        self.stats["events"] += 1
        self.buffer.append((ts, event))
        self.max_ts = ts if self.max_ts is None else max(self.max_ts, ts)
        return self._close_until(self.max_ts - self.lateness)

    def flush(self) -> List[pd.DataFrame]:
        if self.max_ts is None:
            return []
        return self._close_until(self.max_ts.floor(WINDOW) + WINDOW)

    def _close_until(self, watermark: pd.Timestamp) -> List[pd.DataFrame]:
        closed = []
        while self.next_window is not None and self.next_window + WINDOW <= watermark:
            closed.append(self._close(self.next_window))
            self.next_window = self.next_window + WINDOW
        return closed

    def _close(self, w0: pd.Timestamp) -> pd.DataFrame:
        w1 = w0 + WINDOW
        current = [e for ts, e in self.buffer if ts < w1]
        self.buffer = [(ts, e) for ts, e in self.buffer if ts >= w1]
        events = normalize(current)
        windows, self.memory = window_features(events, self.bundle.devices, w0, w1,
                                               memory=self.memory, history=self.history)
        keep = ["device_id", "window_start"] + list(ROLLING.values())
        history = pd.concat([self.history[keep], windows[keep]], ignore_index=True)
        self.history = (history.sort_values("window_start")
                        .groupby("device_id").tail(ROLL_WINDOWS - 1).reset_index(drop=True))
        scored = score_windows(self.bundle, windows)
        self.stats["windows"] += len(windows)
        self.stats["ml_alerts"] += int(scored["alert_ml"].sum())
        return scored


def follow(path: Path, from_start: bool = False, poll: float = 0.2,
           stop: Optional[threading.Event] = None) -> Iterator[Optional[str]]:
    """Yield appended lines (like tail -F). Yields None when idle. Survives rotation."""
    path = Path(path)
    while not path.exists():
        if stop is not None and stop.is_set():
            return
        time.sleep(poll)
    fh = path.open("r", encoding="utf-8", errors="replace")
    inode = os.fstat(fh.fileno()).st_ino
    if not from_start:
        fh.seek(0, os.SEEK_END)
    partial = ""
    while True:
        line = fh.readline()
        if line:
            partial += line
            if partial.endswith("\n"):
                yield partial
                partial = ""
            continue
        if stop is not None and stop.is_set():
            return
        try:
            stat = os.stat(path)
            if stat.st_ino != inode or stat.st_size < fh.tell():
                fh.close()
                fh = path.open("r", encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
                partial = ""
        except FileNotFoundError:
            pass
        yield None
        time.sleep(poll)


# ---------------------------------------------------------------- console output

class Console:
    def __init__(self, color: Optional[bool] = None, stream=sys.stdout):
        self.stream = stream
        self.color = stream.isatty() if color is None else color
        self.lock = threading.Lock()

    def _c(self, code: str, text: str) -> str:
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def say(self, tag: str, text: str, code: str = "0") -> None:
        with self.lock:
            print("%s %s" % (self._c(code, tag), text), file=self.stream, flush=True)

    def alert(self, alert: Dict) -> None:
        code = "1;31" if alert["severity"] == "high" else "1;33"
        rule = "100622" if alert["severity"] == "high" else "100621"
        self.say("[ML %-6s]" % alert["severity"].upper(),
                 "%-8s %s  votes %d/3  window %s  -> Wazuh rule %s" % (
                     alert["device_id"], alert["reasons"], alert["votes"],
                     alert["window_start"][11:16], rule), code)


class Throttle:
    """Analyst-friendly output: one alert per device per `quiet` period unless the
    severity escalates. (Batch evaluation is per window and is not throttled.)"""
    RANK = {"medium": 1, "high": 2}

    def __init__(self, quiet: pd.Timedelta = pd.Timedelta("30min")):
        self.quiet = quiet
        self.last: Dict[str, Tuple[pd.Timestamp, int]] = {}
        self.suppressed = 0

    def __call__(self, alerts: List[Dict]) -> List[Dict]:
        kept = []
        for alert in alerts:
            ts = pd.Timestamp(alert["window_start"])
            rank = self.RANK.get(alert["severity"], 0)
            prev = self.last.get(alert["device_id"])
            if prev is None or ts - prev[0] >= self.quiet or rank > prev[1]:
                self.last[alert["device_id"]] = (ts, rank)
                kept.append(alert)
            else:
                self.suppressed += 1
        return kept


def run_scorer(bundle: Bundle, source: Path, alerts_out: Path, console: Console,
               from_start: bool = False, idle_flush: float = 15.0,
               stop: Optional[threading.Event] = None,
               on_scored: Optional[Callable[[pd.DataFrame], None]] = None,
               throttle: Optional[Throttle] = None) -> LiveScorer:
    scorer = LiveScorer(bundle)
    throttle = throttle or Throttle()
    idle_since = time.time()
    flushed = True
    for line in follow(source, from_start=from_start, stop=stop):
        batches: List[pd.DataFrame] = []
        if line is None:
            if not flushed and time.time() - idle_since > idle_flush:
                batches = scorer.flush()
                flushed = True
            if not batches:
                continue
        else:
            event = parse_line(line)
            if event is None:
                continue
            idle_since = time.time()
            flushed = False
            batches = scorer.add(event)
        for scored in batches:
            alerts = throttle(to_wazuh_alerts(scored, bundle.model_version))
            scorer.stats["ml_alerts_sent"] = scorer.stats.get("ml_alerts_sent", 0) + len(alerts)
            scorer.stats["suppressed_repeats"] = throttle.suppressed
            if alerts:
                write_ml_alerts(alerts, alerts_out)
                for alert in alerts:
                    console.alert(alert)
            if on_scored is not None:
                on_scored(scored)
    return scorer


def replay(events: List[Dict], incidents: List[Incident], out: Path, speed: float,
           console: Console, stop: Optional[threading.Event] = None) -> int:
    """Append events to `out` at `speed` x real time, announcing scripted incidents."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not events:
        return 0
    starts = sorted({(inc.start, inc.scenario, inc.incident_id): inc for inc in incidents}.items())
    announced = set()
    t0_sim = float(events[0]["ts"])  # type: ignore[arg-type]
    t0_real = time.time()
    written = 0
    with out.open("a", encoding="utf-8") as fh:
        for event in events:
            if stop is not None and stop.is_set():
                break
            ts = float(event["ts"])  # type: ignore[arg-type]
            delay = t0_real + (ts - t0_sim) / speed - time.time()
            if delay > 0:
                fh.flush()
                time.sleep(delay)
            for (start, scenario, incident_id), inc in starts:
                if incident_id not in announced and start.timestamp() <= ts:
                    announced.add(incident_id)
                    devices = sorted({i.device_id for i in incidents if i.incident_id == incident_id})
                    category, mitre, rule, _ = SCENARIOS[scenario]
                    label = "ATTACK" if category == "attack" else "BENIGN"
                    expect = ("signature rule %s should fire" % rule if rule != "none"
                              else "no signature rule covers this")
                    console.say("[%s %s]" % (label, iso(ts)[11:16]),
                                "%s on %s (%s) - %s" % (scenario, ", ".join(devices), mitre, expect),
                                "1;35" if category == "attack" else "1;36")
            fh.write(to_json_line(event) + "\n")
            written += 1
    return written


def demo_events(minutes: float, speed: float, seed: int) -> Tuple[List[Dict], List[Incident]]:
    """Demo stream whose simulated clock ends at the real time the replay finishes."""
    real_seconds = minutes * 60 / speed
    end = pd.Timestamp.now(tz="UTC") + pd.Timedelta(seconds=real_seconds)
    start = (end - pd.Timedelta(minutes=minutes)).floor(WINDOW)
    return simulate_demo(start, minutes=minutes, seed=seed)
