import json

from iotsoc.wazuh_io import normalize, parse_line

RAW = {"iotsoc": "gateway", "ts": "2026-09-19T15:10:05.000Z", "kind": "flow",
       "device_id": "cam-04", "device_type": "camera", "device_ip": "10.20.2.14",
       "dst_ip": "203.0.113.77", "dst_port": 443, "proto": "tcp", "dst_zone": "external",
       "bytes_out": 5000000, "bytes_in": 30000}


def test_raw_and_wazuh_archive_forms_normalise_identically():
    archive_full_log = {"timestamp": "2026-09-19T15:10:06.123+0000", "agent": {"id": "000"},
                        "decoder": {"name": "json"}, "full_log": json.dumps(RAW),
                        "data": {k: str(v) for k, v in RAW.items()},
                        "location": "/var/log/iotsoc/gateway.json"}
    archive_data_only = dict(archive_full_log, full_log="not json")
    frames = [normalize([parse_line(json.dumps(x))])
              for x in (RAW, archive_full_log, archive_data_only)]
    for frame in frames[1:]:
        assert frame.equals(frames[0])
    assert frames[0].loc[0, "bytes_out"] == 5e6


def test_ml_results_are_not_fed_back():
    assert parse_line(json.dumps({"iotsoc": "ml", "device_id": "cam-04"})) is None
    wrapped = {"decoder": {"name": "json"}, "data": {"iotsoc": "ml", "device_id": "x"}}
    assert parse_line(json.dumps(wrapped)) is None
    assert parse_line("not json") is None
