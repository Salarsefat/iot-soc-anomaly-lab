import pandas as pd

from iotsoc.simulate import (DEFAULT_START, SCENARIOS, TEST_DAY_SCHEDULE, incidents_frame,
                             simulate, simulate_demo)
from iotsoc.wazuh_io import normalize


def test_deterministic_and_labelled():
    a, inc_a = simulate(days=2, attack_day=1, seed=3)
    b, inc_b = simulate(days=2, attack_day=1, seed=3)
    assert a == b
    frame = incidents_frame(inc_a)
    assert set(frame["scenario"]) == {s for s, *_ in TEST_DAY_SCHEDULE}
    attacks = frame[frame["category"] == "attack"]
    assert attacks["scenario"].nunique() == 7
    assert (frame["end"] > frame["start"]).all()


def test_ground_truth_not_in_events():
    events, _ = simulate(days=2, attack_day=1, seed=3)
    keys = set().union(*(e.keys() for e in events))
    assert not keys & {"label", "attack", "scenario", "incident_id", "category"}


def test_clean_days_have_no_incidents():
    events, incidents = simulate(days=2, attack_day=None, seed=3)
    assert incidents == []
    frame = normalize(events)
    assert not frame["topic"].isin(["#", "$SYS/#"]).any()
    assert not (frame["fw_signed"] == "false").any()


def test_demo_stream_fits_window():
    start = pd.Timestamp("2026-10-23T08:00:00Z")
    events, incidents = simulate_demo(start, minutes=120)
    ts = [e["ts"] for e in events]
    assert min(ts) >= start.timestamp() and max(ts) < start.timestamp() + 7200
    assert {i.scenario for i in incidents} <= set(SCENARIOS)
