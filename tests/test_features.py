import pandas as pd
import pytest

from iotsoc.features import (WINDOW, DeviceBaseline, label_entropy, mark_novelty,
                             window_features)
from iotsoc.wazuh_io import normalize

T0 = pd.Timestamp("2026-09-14T00:00:00Z")


def ev(minutes, kind="flow", device="d1", **kw):
    base = {"ts": (T0 + pd.Timedelta(minutes=minutes)).isoformat(), "kind": kind,
            "device_id": device, "device_type": "sensor"}
    base.update(kw)
    return base


def test_idle_windows_are_zero_rows():
    events = normalize([ev(1, "mqtt_publish", bytes=100)])
    windows, _ = window_features(events, {"d1": "sensor", "d2": "sensor"}, T0, T0 + 3 * WINDOW)
    assert len(windows) == 6
    assert windows["mqtt_pub"].sum() == 1
    assert (windows[windows["device_id"] == "d2"]["mqtt_pub"] == 0).all()


def test_rejects_unaligned_bounds():
    with pytest.raises(ValueError):
        window_features(normalize([]), {"d1": "sensor"}, T0 + pd.Timedelta("1min"), T0 + WINDOW)


def test_novelty_uses_24h_horizon_and_memory():
    flows = [ev(0, dst_ip="1.1.1.1", dst_zone="external", bytes_out=1),
             ev(10, dst_ip="1.1.1.1", dst_zone="external", bytes_out=1),
             ev(60 * 25, dst_ip="1.1.1.1", dst_zone="external", bytes_out=1)]
    marked, memory = mark_novelty(normalize(flows))
    assert marked["is_new_dst"].tolist() == [True, False, True]
    again, _ = mark_novelty(normalize([ev(60 * 26, dst_ip="1.1.1.1", dst_zone="external")]),
                            memory)
    assert again["is_new_dst"].tolist() == [False]


def test_rolling_hour_accumulates_low_and_slow():
    fails = [ev(5 * k + 1, "device_auth", outcome="failure") for k in range(12)]
    windows, _ = window_features(normalize(fails), {"d1": "sensor"}, T0, T0 + 12 * WINDOW)
    assert windows["auth_fail"].max() == 1
    assert windows["auth_fail_1h"].iloc[-1] == 12


def test_entropy():
    assert label_entropy("cloud.camvendor.example") < 2.5
    assert label_entropy("k3j9x0q2m7w1zt.example") > 3.3


def test_baseline_floor_and_type_fallback():
    rows = []
    for k in range(50):
        rows.append({"device_id": "d1", "device_type": "sensor", "period": "night",
                     "window_start": T0 + k * WINDOW, "auth_fail": 0.0, "mqtt_pub": 3.0})
    train = pd.DataFrame(rows)
    base = DeviceBaseline(features=["auth_fail", "mqtt_pub"]).fit(train)
    test = pd.DataFrame([{"device_id": "d1", "device_type": "sensor", "period": "night",
                          "auth_fail": 60.0, "mqtt_pub": 3.0},
                         {"device_id": "new", "device_type": "sensor", "period": "night",
                          "auth_fail": 0.0, "mqtt_pub": 3.0}])
    z = base.transform(test)
    assert z.loc[0, "auth_fail"] > 5 and abs(z.loc[0, "mqtt_pub"]) < 1e-9
    assert abs(z.loc[1, "auth_fail"]) < 1e-9


def test_explain_names_features_even_when_deviations_are_small():
    from iotsoc.features import explain
    windows = pd.DataFrame({"mqtt_conn_ok": [1.0, 0.0], "ext_bytes_out": [3e7, 0.0]})
    z = pd.DataFrame({"mqtt_conn_ok": [1.4, 0.1], "ext_bytes_out": [0.0, 0.0]})
    low = pd.DataFrame({"mqtt_conn_ok": [0.0, 0.0], "ext_bytes_out": [0.0, 0.0]})
    high = pd.DataFrame({"mqtt_conn_ok": [0.0, 0.0], "ext_bytes_out": [4e4, 4e4]})
    reasons = explain(windows, z, (low, high))
    assert reasons[0] == "small deviations only: MQTT connections 1 (usual 0)"
    assert reasons[1] == "combination of small deviations"
    z.loc[0, "ext_bytes_out"] = 9.0
    assert explain(windows, z, (low, high))[0].startswith("bytes sent to the internet 30.0 MB")
