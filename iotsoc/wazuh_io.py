"""Read gateway events (raw or via Wazuh) and write ML results Wazuh can ingest.

Accepted input lines:
  1. Raw gateway JSON written by the simulator / replay ("iotsoc": "gateway").
  2. Wazuh archives.json or alerts.json entries whose JSON decoder produced
     `data.iotsoc == "gateway"`. Wazuh may turn numbers into strings, so every
     numeric field is coerced. When `full_log` holds the original JSON line it
     is preferred, because it keeps the original types.
Lines produced by this project's ML exporter ("iotsoc": "ml") are skipped so
results are never fed back into the detector.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import pandas as pd

COLUMNS = ["ts", "kind", "device_id", "device_type", "device_ip", "outcome", "account",
           "service", "src_ip", "client_id", "reason", "topic", "bytes", "dst_ip", "dst_port",
           "proto", "dst_zone", "allowlisted", "bytes_out", "bytes_in", "qname",
           "fw_version", "fw_source", "fw_signed", "setting"]
NUMERIC = ["bytes", "dst_port", "bytes_out", "bytes_in"]


def extract_gateway_event(record: Dict) -> Optional[Dict]:
    """Return the gateway event inside a raw or Wazuh-wrapped record, else None."""
    if record.get("iotsoc") == "gateway":
        return record
    if record.get("iotsoc") == "ml":
        return None
    full_log = record.get("full_log")
    if isinstance(full_log, str) and full_log.startswith("{"):
        try:
            inner = json.loads(full_log)
        except json.JSONDecodeError:
            inner = None
        if isinstance(inner, dict) and inner.get("iotsoc") == "gateway":
            return inner
    data = record.get("data")
    if isinstance(data, dict) and data.get("iotsoc") == "gateway":
        return data
    return None


def parse_line(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None
    return extract_gateway_event(record)


def iter_events(lines: Iterable[str]) -> Iterator[Dict]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event


def normalize(records: List[Dict]) -> pd.DataFrame:
    """Records (dicts with ISO or epoch `ts`) -> typed DataFrame sorted by time."""
    frame = pd.DataFrame.from_records(records) if records else pd.DataFrame(columns=COLUMNS)
    for column in COLUMNS:
        if column not in frame.columns:
            frame[column] = pd.NA
    frame = frame[COLUMNS].copy()
    ts = frame["ts"]
    if len(frame) and pd.api.types.is_numeric_dtype(ts):
        frame["ts"] = pd.to_datetime(ts.astype(float), unit="s", utc=True)
    else:
        frame["ts"] = pd.to_datetime(ts, utc=True, format="ISO8601")
    # One resolution everywhere (pandas 3 parses ISO strings to microseconds).
    frame["ts"] = frame["ts"].astype("datetime64[ns, UTC]")
    for column in NUMERIC:
        frame[column] = pd.to_numeric(frame[column], errors="coerce").astype(float)
    for column in COLUMNS:
        if column not in NUMERIC and column != "ts":
            frame[column] = frame[column].astype("object").where(frame[column].notna(), None)
    frame = frame.dropna(subset=["ts", "device_id", "kind"])
    return frame.sort_values("ts", kind="stable").reset_index(drop=True)


def read_events(path: Path) -> Tuple[pd.DataFrame, int]:
    """Read a JSONL file (raw gateway or Wazuh archives). Returns (events, skipped)."""
    records: List[Dict] = []
    skipped = 0
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            event = parse_line(line)
            if event is None:
                if line.strip():
                    skipped += 1
                continue
            records.append(event)
    return normalize(records), skipped


def write_ml_alerts(alerts: Iterable[Dict], path: Path, append: bool = True) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a" if append else "w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert, separators=(",", ":")) + "\n")
            n += 1
    return n
