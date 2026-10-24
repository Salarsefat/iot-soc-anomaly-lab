"""The live scorer must produce exactly the batch features and scores."""
import copy

import numpy as np
import pandas as pd
import pytest

from iotsoc.features import ML_FEATURES, RULE_FEATURES, WINDOW, window_features
from iotsoc.live import LiveScorer
from iotsoc.pipeline import Split, device_map, score_windows, train_bundle
from iotsoc.simulate import DEFAULT_START, iso, simulate, simulate_demo
from iotsoc.wazuh_io import normalize


@pytest.fixture(scope="module")
def bundle():
    events, _ = simulate(days=5, attack_day=None, seed=5)
    split = Split.by_days(DEFAULT_START, test=0)
    devices = device_map()
    windows, memory = window_features(normalize(events), devices, split.start, split.end)
    return train_bundle(windows, memory, split, devices)


def test_live_equals_batch(bundle):
    start = pd.Timestamp("2026-10-23T08:00:00Z")
    events, _ = simulate_demo(start, minutes=60, seed=11)
    # batch
    memory, history = bundle.rebased(start)
    batch, _ = window_features(normalize(events), bundle.devices, start,
                               start + pd.Timedelta(minutes=60), memory=copy.deepcopy(memory),
                               history=history)
    batch_scored = score_windows(bundle, batch)
    # live (ISO timestamps, as they arrive from Wazuh)
    scorer = LiveScorer(bundle)
    parts = []
    for event in events:
        record = dict(event, ts=iso(float(event["ts"])))
        parts.extend(scorer.add(record))
    parts.extend(scorer.flush())
    live = pd.concat(parts, ignore_index=True)
    live = live[live["window_start"] < start + pd.Timedelta(minutes=60)]
    key = ["window_start", "device_id"]
    a = batch_scored.sort_values(key).reset_index(drop=True)
    b = live.sort_values(key).reset_index(drop=True)
    assert len(a) == len(b) == 12 * len(bundle.devices)
    cols = ML_FEATURES + RULE_FEATURES + ["score_iforest", "score_lof", "score_autoencoder",
                                          "score_iforest_raw"]
    np.testing.assert_allclose(a[cols].to_numpy(float), b[cols].to_numpy(float), rtol=1e-9)
    assert (a["alert_hybrid"] == b["alert_hybrid"]).all()
    assert scorer.stats["late"] == 0


def test_late_events_are_counted_not_crashing(bundle):
    scorer = LiveScorer(bundle)
    t = pd.Timestamp("2026-10-23T08:00:00Z")
    base = {"iotsoc": "gateway", "kind": "mqtt_publish", "device_id": "sens-01",
            "device_type": "sensor", "bytes": 100}
    scorer.add(dict(base, ts=(t + pd.Timedelta(minutes=1)).isoformat()))
    out = scorer.add(dict(base, ts=(t + pd.Timedelta(minutes=12)).isoformat()))
    assert len(out) == 2                                   # two windows closed
    scorer.add(dict(base, ts=(t + pd.Timedelta(minutes=2)).isoformat()))
    assert scorer.stats["late"] == 1


def test_reordered_events_within_a_minute_are_not_lost(bundle):
    """Wazuh can deliver events slightly out of order; none may be dropped."""
    import random
    start = pd.Timestamp("2026-10-23T08:00:00Z")
    events, _ = simulate_demo(start, minutes=30, seed=3)
    rng = random.Random(1)
    shuffled = sorted(events, key=lambda e: float(e["ts"]) + rng.uniform(0, 60))
    scorer = LiveScorer(bundle)
    for event in shuffled:
        scorer.add(dict(event, ts=iso(float(event["ts"]))))
    scorer.flush()
    assert scorer.stats["late"] == 0
    assert scorer.stats["events"] == len(events)
