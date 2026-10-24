"""Glue: events -> windows -> baseline -> detectors -> scored windows -> alerts."""
from __future__ import annotations

import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import sklearn

from . import __version__
from .detectors import DetectorSuite, rule_names
from .features import (ML_FEATURES, ROLL_WINDOWS, ROLLING, WINDOW, DeviceBaseline, Memory,
                       explain, window_features)
from .fleet import build_fleet

DAY = pd.Timedelta("1D")


@dataclass
class Split:
    start: pd.Timestamp
    train_start: pd.Timestamp
    calibration_start: pd.Timestamp
    test_start: pd.Timestamp
    end: pd.Timestamp

    @classmethod
    def by_days(cls, start: pd.Timestamp, warmup: int = 1, train: int = 3,
                calibration: int = 1, test: int = 1) -> "Split":
        return cls(start, start + warmup * DAY, start + (warmup + train) * DAY,
                   start + (warmup + train + calibration) * DAY,
                   start + (warmup + train + calibration + test) * DAY)

    def part(self, windows: pd.DataFrame, name: str) -> pd.DataFrame:
        bounds = {"train": (self.train_start, self.calibration_start),
                  "calibration": (self.calibration_start, self.test_start),
                  "test": (self.test_start, self.end)}[name]
        mask = (windows["window_start"] >= bounds[0]) & (windows["window_start"] < bounds[1])
        return windows[mask].reset_index(drop=True)


@dataclass
class Bundle:
    """Everything the live scorer needs, saved with joblib."""
    devices: Dict[str, str]
    baseline: DeviceBaseline
    suite: DetectorSuite
    memory: Memory
    history: pd.DataFrame
    data_end: pd.Timestamp
    meta: Dict[str, object] = field(default_factory=dict)

    @property
    def model_version(self) -> str:
        return "iotsoc-%s-fpr%s" % (__version__, self.suite.target_fpr)

    def rebased(self, new_end: pd.Timestamp):
        """Memory and rolling history shifted so the training data ends at `new_end`."""
        offset = pd.Timestamp(new_end) - self.data_end
        memory = {k: v + offset for k, v in self.memory.items()}
        history = self.history.copy()
        history["window_start"] = history["window_start"] + offset
        return memory, history


def device_map(fleet=None) -> Dict[str, str]:
    return {d.device_id: d.device_type for d in (fleet or build_fleet())}


def train_bundle(windows: pd.DataFrame, memory: Memory, split: Split, devices: Dict[str, str],
                 target_fpr: float = 0.002, seed: int = 42) -> Bundle:
    train = split.part(windows, "train")
    calibration = split.part(windows, "calibration")
    baseline = DeviceBaseline().fit(train)
    suite = DetectorSuite(target_fpr=target_fpr, seed=seed)
    suite.fit(baseline.transform(train), train)
    suite.calibrate(baseline.transform(calibration), calibration)
    # Novelty memory and rolling history as they stood at the end of calibration.
    cutoff = split.test_start
    kept = {k: v for k, v in memory.items() if v < cutoff}
    tail = calibration[calibration["window_start"] >= cutoff - ROLL_WINDOWS * WINDOW]
    history = tail[["device_id", "window_start"] + list(ROLLING.values())].copy()
    meta = {
        "iotsoc_version": __version__, "python": platform.python_version(),
        "sklearn": sklearn.__version__, "pandas": pd.__version__, "numpy": np.__version__,
        "train_windows": int(len(train)), "calibration_windows": int(len(calibration)),
        "train_period": [str(split.train_start), str(split.calibration_start)],
        "calibration_period": [str(split.calibration_start), str(split.test_start)],
        "target_fpr": target_fpr, "thresholds": suite.thresholds, "features": ML_FEATURES,
    }
    return Bundle(devices, baseline, suite, kept, history, cutoff, meta)


def score_windows(bundle: Bundle, windows: pd.DataFrame, with_reasons: bool = True) -> pd.DataFrame:
    z = bundle.baseline.transform(windows)
    scored = bundle.suite.score(z, windows)
    out = pd.concat([windows.reset_index(drop=True), scored.reset_index(drop=True)], axis=1)
    out["reasons"] = ""
    if with_reasons:
        flagged = out.index[out["alert_hybrid"]]
        if len(flagged):
            sub = windows.reset_index(drop=True).loc[flagged]
            out.loc[flagged, "reasons"] = explain(
                sub, z.reset_index(drop=True).loc[flagged], bundle.baseline.usual(sub))
    return out


def to_wazuh_alerts(scored: pd.DataFrame, model_version: str) -> List[Dict[str, object]]:
    """ML-originated alerts only (rule hits are raised by Wazuh itself)."""
    alerts = []
    for _, row in scored[scored["alert_ml"]].iterrows():
        voters = [n for n in ("iforest", "lof", "autoencoder") if row["alert_" + n]]
        window_start = pd.Timestamp(row["window_start"])
        alerts.append({
            "iotsoc": "ml", "detector": "autoencoder+vote", "model_version": model_version,
            "device_id": row["device_id"], "device_type": row["device_type"],
            "window_start": window_start.isoformat().replace("+00:00", "Z"),
            "window_end": (window_start + WINDOW).isoformat().replace("+00:00", "Z"),
            "severity": row["severity"], "votes": int(row["votes"]),
            "voters": ",".join(voters) or "none", "score": round(float(row["score_ml"]), 3),
            "signature_overlap": ",".join(rule_names(row)) or "none",
            "reasons": row["reasons"],
        })
    return alerts
