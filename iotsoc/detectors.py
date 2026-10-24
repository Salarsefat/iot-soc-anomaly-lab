"""Signature rules and four unsupervised detectors, calibrated on clean data.

Detectors
  rules        static thresholds mirroring wazuh/rules/iotsoc_rules.xml
  iforest_raw  Isolation Forest on raw (log) features, no per-device baseline
               (the common "throw the features at an Isolation Forest" approach)
  iforest      Isolation Forest on self-baselined z-scores
  lof          Local Outlier Factor (novelty mode) on the same z-scores
  autoencoder  small neural network that reconstructs z-scores; error = score
  ensemble     alert when at least 2 of {iforest, lof, autoencoder} agree
  ml           deployed ML policy: autoencoder OR ensemble; severity "high" when
               a second model (or a signature rule) agrees, otherwise "medium"
  hybrid       rules OR ml (what the SOC actually receives)

Thresholds come from a separate calibration period: each score threshold is
the (1 - target_fpr) quantile of that detector's scores on calibration data.
Labels are never used for fitting or for thresholds.
"""
from __future__ import annotations

import warnings
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor

from .features import ML_FEATURES

ML_DETECTORS = ["iforest", "lof", "autoencoder"]
ALL_SCORED = ["iforest_raw"] + ML_DETECTORS
DEVICE_TYPES = ["camera", "hvac", "lock", "sensor"]

# Mirrors of the Wazuh rules (per 5-minute window; Wazuh uses sliding time frames).
RULES = {
    "100602": ("auth_fail", 10, "Brute force: 10+ failed device logins"),
    "100604": ("wildcard_sub", 1, "Wildcard MQTT subscription"),
    "100606": ("fw_unsigned", 1, "Unsigned firmware installed"),
    "100608": ("int_unexpected", 20, "Internal scan: 20+ non-allowlisted internal connections"),
}


def rule_hits(windows: pd.DataFrame) -> pd.DataFrame:
    hits = pd.DataFrame(index=windows.index)
    for rule_id, (feature, threshold, _) in RULES.items():
        hits["rule_" + rule_id] = windows[feature].to_numpy() >= threshold
    hits["alert_rules"] = hits.any(axis=1)
    return hits


def raw_matrix(windows: pd.DataFrame) -> np.ndarray:
    logs = np.log1p(windows[ML_FEATURES].astype(float).to_numpy())
    types = np.stack([(windows["device_type"] == t).to_numpy(dtype=float) for t in DEVICE_TYPES],
                     axis=1)
    return np.hstack([logs, types])


class DetectorSuite:
    def __init__(self, target_fpr: float = 0.002, seed: int = 42):
        if not 0 < target_fpr < 0.5:
            raise ValueError("target_fpr must be between 0 and 0.5")
        self.target_fpr = target_fpr
        self.seed = seed
        self.thresholds: Dict[str, float] = {}

    def fit(self, z_train: pd.DataFrame, windows_train: pd.DataFrame) -> "DetectorSuite":
        z = z_train[ML_FEATURES].to_numpy()
        self.models = {
            "iforest_raw": IsolationForest(n_estimators=300, random_state=self.seed, n_jobs=1)
            .fit(raw_matrix(windows_train)),
            "iforest": IsolationForest(n_estimators=300, random_state=self.seed, n_jobs=1).fit(z),
            # LOF breaks on duplicate points (zero k-distance), and idle IoT windows
            # repeat a lot, so it is fitted on the distinct training rows.
            "lof": LocalOutlierFactor(n_neighbors=50, novelty=True).fit(np.unique(z, axis=0)),
        }
        autoencoder = MLPRegressor(hidden_layer_sizes=(32, 8, 32), activation="tanh",
                                   alpha=1e-4, learning_rate_init=1e-3, max_iter=300,
                                   early_stopping=True, n_iter_no_change=15,
                                   random_state=self.seed)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.models["autoencoder"] = autoencoder.fit(z, z)
        return self

    def raw_scores(self, z: pd.DataFrame, windows: pd.DataFrame) -> pd.DataFrame:
        """Higher = more unusual, for every detector."""
        zm = z[ML_FEATURES].to_numpy()
        scores = pd.DataFrame(index=windows.index)
        scores["score_iforest_raw"] = -self.models["iforest_raw"].score_samples(raw_matrix(windows))
        scores["score_iforest"] = -self.models["iforest"].score_samples(zm)
        scores["score_lof"] = -self.models["lof"].score_samples(zm)
        recon = self.models["autoencoder"].predict(zm)
        scores["score_autoencoder"] = np.mean((zm - recon) ** 2, axis=1)
        return scores

    def calibrate(self, z_cal: pd.DataFrame, windows_cal: pd.DataFrame) -> "DetectorSuite":
        scores = self.raw_scores(z_cal, windows_cal)
        q = 1 - self.target_fpr
        for name in ALL_SCORED:
            self.thresholds[name] = float(np.quantile(scores["score_" + name], q,
                                                      method="higher"))
        return self

    def score(self, z: pd.DataFrame, windows: pd.DataFrame) -> pd.DataFrame:
        if not self.thresholds:
            raise RuntimeError("calibrate() before score()")
        out = self.raw_scores(z, windows)
        for name in ALL_SCORED:
            out["alert_" + name] = out["score_" + name] > self.thresholds[name]
        ratios = np.stack([np.log(np.maximum(out["score_" + n].to_numpy(), 1e-12)
                                  / self.thresholds[n]) for n in ML_DETECTORS], axis=1)
        out["votes"] = out[["alert_" + n for n in ML_DETECTORS]].sum(axis=1).astype(int)
        out["score_ensemble"] = ratios.mean(axis=1)
        out["alert_ensemble"] = out["votes"] >= 2
        # Deployed ML policy: the autoencoder is the primary detector; agreement of
        # a second model (or a signature hit) raises the severity for triage.
        out["alert_ml"] = out["alert_autoencoder"] | out["alert_ensemble"]
        out["score_ml"] = np.maximum(ratios[:, ML_DETECTORS.index("autoencoder")],
                                     out["score_ensemble"].to_numpy())
        hits = rule_hits(windows)
        out = pd.concat([out, hits], axis=1)
        out["alert_hybrid"] = out["alert_rules"] | out["alert_ml"]
        top = out["score_ml"].max() if len(out) else 0.0
        out["score_hybrid"] = np.where(out["alert_rules"], max(top, 0.0) + 1.0, out["score_ml"])
        out["severity"] = np.select(
            [out["alert_ml"] & (out["alert_ensemble"] | out["alert_rules"]), out["alert_ml"]],
            ["high", "medium"], default="none")
        return out


def rule_names(row: pd.Series) -> List[str]:
    return [rule_id for rule_id in RULES if bool(row.get("rule_" + rule_id, False))]
