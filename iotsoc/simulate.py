"""Simulate IoT gateway telemetry with labelled attacks and benign surprises.

The simulator writes the kind of JSON lines an IoT edge gateway (MQTT broker +
firewall flow log + DNS forwarder + device-management proxy) could emit. Each
line is one event. Ground truth is kept in a separate incident table and is
never written into the event stream, so detectors cannot see it.

Timeline of the default dataset (6 days, UTC):
  day 0          warm-up (fills the 24 h "seen before" memory; not used to train)
  days 1-3       training (normal behaviour only)
  day 4          calibration (normal behaviour only; used to set thresholds)
  day 5          test (normal behaviour + 7 attacks + 3 benign-but-unusual events)
"""
from __future__ import annotations

import json
import string
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from .fleet import (BMS_IP, CAMERA_CDN_POOL, NTP_DOMAIN, NTP_POOL, NVR_IP,
                    Device, build_fleet, fleet_index)

DEFAULT_START = pd.Timestamp("2026-09-14T00:00:00Z")
HOUR = 3600.0
DAY = 86400.0
ADMIN_WORKSTATION = "10.20.9.30"

Event = Dict[str, object]


@dataclass
class Incident:
    """Ground truth for one scripted activity (attack or benign surprise)."""
    incident_id: str
    category: str            # "attack" or "benign"
    scenario: str
    device_id: str
    start: pd.Timestamp
    end: pd.Timestamp
    mitre: str
    signature_rule: str      # Wazuh/rule id expected to fire, or "none"
    description: str

    def as_row(self) -> Dict[str, object]:
        return {
            "incident_id": self.incident_id, "category": self.category,
            "scenario": self.scenario, "device_id": self.device_id,
            "start": self.start.isoformat(), "end": self.end.isoformat(),
            "mitre": self.mitre, "signature_rule": self.signature_rule,
            "description": self.description,
        }


# --------------------------------------------------------------------------
# Small random-process helpers (times are float epoch seconds)
# --------------------------------------------------------------------------

def _periodic(rng, t0: float, t1: float, period: float, jitter: float,
              phase: Optional[float] = None) -> np.ndarray:
    """Regular events. With `phase`, the schedule is anchored to the epoch, so a
    device keeps the same rhythm across days (as real firmware timers do)."""
    if phase is None:
        first = t0 + rng.uniform(0, period)
    else:
        first = np.ceil((t0 - phase) / period) * period + phase
    n = int(max(0.0, t1 - first) // period) + 1
    times = first + np.arange(n) * period + rng.normal(0, jitter, n)
    return np.sort(times[(times >= t0) & (times < t1)])


def device_phase(dev: Device, process: str, period: float) -> float:
    """Stable per-device timer phase (same in training, test and live demo)."""
    key = zlib.crc32(("%s/%s" % (dev.device_id, process)).encode())
    return float(np.random.default_rng(key).uniform(0, period))


def _business(times: np.ndarray) -> np.ndarray:
    hours = (times % DAY) // HOUR
    return (hours >= 8) & (hours < 18)


def _poisson(rng, t0: float, t1: float, day_rate: float, night_rate: float) -> np.ndarray:
    """Inhomogeneous Poisson process; rates are events per hour."""
    peak = max(day_rate, night_rate)
    if peak <= 0 or t1 <= t0:
        return np.empty(0)
    n = rng.poisson(peak * (t1 - t0) / HOUR)
    times = np.sort(rng.uniform(t0, t1, n))
    rate = np.where(_business(times), day_rate, night_rate)
    return times[rng.uniform(0, 1, n) < rate / peak]


def _ev(dev: Device, ts: float, kind: str, **fields) -> Event:
    event: Event = {"iotsoc": "gateway", "ts": float(ts), "kind": kind,
                    "device_id": dev.device_id, "device_type": dev.device_type,
                    "device_ip": dev.ip}
    event.update(fields)
    return event


def _flow(dev: Device, ts: float, dst_ip: str, dst_port: int, proto: str,
          bytes_out: float, bytes_in: float, allowlisted: Optional[bool] = None) -> Event:
    internal = dst_ip.startswith("10.")
    fields = {"dst_ip": dst_ip, "dst_port": int(dst_port), "proto": proto,
              "dst_zone": "internal" if internal else "external",
              "bytes_out": int(bytes_out), "bytes_in": int(bytes_in)}
    if internal:
        fields["allowlisted"] = "yes" if allowlisted else "no"
    return _ev(dev, ts, "flow", **fields)


def _random_label(rng, length: int) -> str:
    alphabet = list(string.ascii_lowercase + string.digits)
    return "".join(rng.choice(alphabet, size=length))


# --------------------------------------------------------------------------
# Normal behaviour
# --------------------------------------------------------------------------

def normal_traffic(rng, dev: Device, t0: float, t1: float) -> List[Event]:
    out: List[Event] = []
    pool = dev.vendor_pool

    # Occasional MQTT reconnects (keep-alive timeouts, Wi-Fi roaming).
    for ts in _poisson(rng, t0, t1, 2 / 24, 2 / 24):
        out.append(_ev(dev, ts, "mqtt_connect", outcome="success",
                       client_id=dev.device_id, account=dev.device_id))
        out.append(_ev(dev, ts + 0.2, "mqtt_subscribe", topic=dev.topic("cmd")))

    # DNS + vendor cloud + NTP.
    for ts in _periodic(rng, t0, t1, 1800, 120, device_phase(dev, "dns", 1800)):
        out.append(_ev(dev, ts, "dns_query", qname=dev.vendor_domain))
    for ts in _periodic(rng, t0, t1, HOUR, 60, device_phase(dev, "ntp", HOUR)):
        out.append(_ev(dev, ts, "dns_query", qname=NTP_DOMAIN))
        out.append(_flow(dev, ts + 0.1, str(rng.choice(NTP_POOL)), 123, "udp", 76, 76))
    cloud_period = {"sensor": 900, "camera": 600, "lock": 1800, "hvac": HOUR}[dev.device_type]
    cloud_bytes = {"sensor": (2e3, 6e3), "camera": (1e4, 4e4),
                   "lock": (1e3, 3e3), "hvac": (3e3, 9e3)}[dev.device_type]
    for ts in _periodic(rng, t0, t1, cloud_period, 30,
                             device_phase(dev, "cloud", cloud_period)):
        out.append(_flow(dev, ts, str(rng.choice(pool)), 443, "tcp",
                         rng.uniform(*cloud_bytes), rng.uniform(5e2, 2e3)))

    if dev.device_type == "sensor":
        for ts in _periodic(rng, t0, t1, 120, 5, device_phase(dev, "publish", 120)):
            out.append(_ev(dev, ts, "mqtt_publish", topic=dev.topic("telemetry"),
                           bytes=int(rng.uniform(90, 130))))

    elif dev.device_type == "camera":
        for ts in _poisson(rng, t0, t1, 12, 2):
            out.append(_ev(dev, ts, "mqtt_publish", topic=dev.topic("motion"),
                           bytes=int(rng.uniform(300, 600))))
        for ts in _periodic(rng, t0, t1, 300, 3, device_phase(dev, "nvr", 300)):
            mb = 50e6 if _business(np.array([ts]))[0] else 35e6
            out.append(_flow(dev, ts, NVR_IP, 554, "tcp", rng.normal(mb, 0.1 * mb),
                             rng.uniform(1e5, 3e5), allowlisted=True))
        for ts in _poisson(rng, t0, t1, 1.5 / 24, 1.5 / 24):   # rotating CDN edge
            out.append(_ev(dev, ts, "dns_query", qname="cdn.camvendor.example"))
            out.append(_flow(dev, ts + 0.1, str(rng.choice(CAMERA_CDN_POOL)), 443, "tcp",
                             rng.uniform(2e3, 8e3), rng.uniform(5e4, 3e5)))
        for ts in _poisson(rng, t0, t1, 4 / 24, 4 / 24):       # internet scanner noise
            out.append(_ev(dev, ts, "device_auth", service="telnet", outcome="failure",
                           account=str(rng.choice(["root", "admin"])),
                           src_ip="198.18.%d.%d" % (rng.integers(0, 256), rng.integers(1, 255))))

    elif dev.device_type == "lock":
        for ts in _poisson(rng, t0, t1, 6, 0.3):
            out.append(_ev(dev, ts, "mqtt_publish", topic=dev.topic("access"),
                           bytes=int(rng.uniform(150, 250))))
        for ts in _periodic(rng, t0, t1, 600, 10, device_phase(dev, "heartbeat", 600)):
            out.append(_ev(dev, ts, "mqtt_publish", topic=dev.topic("heartbeat"),
                           bytes=int(rng.uniform(60, 80))))

    elif dev.device_type == "hvac":
        for ts in _periodic(rng, t0, t1, 60, 2, device_phase(dev, "status", 60)):
            out.append(_ev(dev, ts, "mqtt_publish", topic=dev.topic("status"),
                           bytes=int(rng.uniform(200, 300))))
        for ts in _periodic(rng, t0, t1, 300, 5, device_phase(dev, "bms", 300)):
            out.append(_flow(dev, ts, BMS_IP, 47808, "udp", rng.uniform(4e3, 8e3),
                             rng.uniform(2e3, 4e3), allowlisted=True))
        for ts in _poisson(rng, t0, t1, 0.06, 0.0):            # ~0.6 admin logins per day
            if rng.uniform() < 0.2:
                out.append(_ev(dev, ts - 20, "device_auth", service="ssh", outcome="failure",
                               account="facility-admin", src_ip=ADMIN_WORKSTATION))
            out.append(_ev(dev, ts, "device_auth", service="ssh", outcome="success",
                           account="facility-admin", src_ip=ADMIN_WORKSTATION))
            for k in range(int(rng.integers(0, 3))):
                out.append(_ev(dev, ts + 60 * (k + 1), "config_change",
                               account="facility-admin", setting="setpoint"))
    return out


# --------------------------------------------------------------------------
# Attacks (category = "attack")
# --------------------------------------------------------------------------

def telnet_bruteforce(rng, dev: Device, t0: float, minutes: float = 30,
                      spread_minutes: float = 15) -> Tuple[List[Event], float]:
    """Mirai-style default-credential guessing, then a loader download and scanning."""
    out: List[Event] = []
    attackers = ["203.0.113.21", "203.0.113.22", "203.0.113.23"]
    accounts = ["root", "admin", "support", "user", "guest", "default"]
    t_success = t0 + (minutes - 2) * 60
    for ts in np.sort(rng.uniform(t0, t_success, int(12 * (minutes - 2)))):
        out.append(_ev(dev, ts, "device_auth", service="telnet", outcome="failure",
                       account=str(rng.choice(accounts)), src_ip=str(rng.choice(attackers))))
    out.append(_ev(dev, t_success, "device_auth", service="telnet", outcome="success",
                   account="root", src_ip=attackers[0]))
    t_loader = t0 + minutes * 60
    for k in range(3):
        out.append(_flow(dev, t_loader + 10 * k, "203.0.113.50", 80, "tcp",
                         rng.uniform(1e3, 3e3), rng.uniform(4e5, 8e5)))
    t_end = t_loader + spread_minutes * 60
    for ts in np.sort(rng.uniform(t_loader + 40, t_end, int(30 * spread_minutes))):
        out.append(_flow(dev, ts, "198.18.%d.%d" % (rng.integers(0, 256), rng.integers(1, 255)),
                         23, "tcp", rng.uniform(60, 200), rng.uniform(0, 120)))
    return out, t_end


def lowslow_bruteforce(rng, dev: Device, t0: float, minutes: float = 240) -> Tuple[List[Event], float]:
    """Password guessing kept below per-window thresholds (~15 attempts/hour)."""
    out: List[Event] = []
    accounts = ["admin", "hvac", "maint", "operator", "root"]
    for ts in _poisson(rng, t0, t0 + minutes * 60, 15, 15):
        out.append(_ev(dev, ts, "device_auth", service="ssh", outcome="failure",
                       account=str(rng.choice(accounts)),
                       src_ip="203.0.113.%d" % rng.integers(100, 141)))
    return out, t0 + minutes * 60


def mqtt_recon(rng, dev: Device, t0: float, minutes: float = 15) -> Tuple[List[Event], float]:
    """A compromised sensor tries other broker accounts, then subscribes to everything."""
    out: List[Event] = []
    for k, account in enumerate(["admin", "guest", "test", "bms", "root", "iot"]):
        out.append(_ev(dev, t0 + 20 * k, "mqtt_connect", outcome="failure",
                       reason="bad_credentials", account=account,
                       client_id="probe-%s" % _random_label(rng, 6)))
    t = t0 + 150
    out.append(_ev(dev, t, "mqtt_connect", outcome="success", account=dev.device_id,
                   client_id="probe-%s" % _random_label(rng, 6)))
    for k, topic in enumerate(["#", "$SYS/#", "building/+/lock/+/access", "building/+/hvac/+/cmd"]):
        out.append(_ev(dev, t + 30 + 40 * k, "mqtt_subscribe", topic=topic))
    return out, t0 + minutes * 60


def exfiltration(rng, dev: Device, t0: float, minutes: float = 35) -> Tuple[List[Event], float]:
    """Bulk upload of recordings to an unknown external host over HTTPS."""
    out: List[Event] = [_ev(dev, t0, "dns_query", qname="storage-sync.example")]
    for ts in _periodic(rng, t0 + 5, t0 + minutes * 60, 60, 2):
        out.append(_flow(dev, ts, "203.0.113.77", 443, "tcp",
                         rng.uniform(4e6, 8e6), rng.uniform(2e4, 5e4)))
    return out, t0 + minutes * 60


def c2_beaconing(rng, dev: Device, t0: float, minutes: float = 300) -> Tuple[List[Event], float]:
    """Regular small check-ins to a command server plus algorithmically generated domains."""
    out: List[Event] = []
    for ts in _periodic(rng, t0, t0 + minutes * 60, 60, 3):
        out.append(_flow(dev, ts, "203.0.113.66", 8443, "tcp",
                         rng.uniform(300, 600), rng.uniform(200, 400)))
    for ts in _periodic(rng, t0, t0 + minutes * 60, 600, 30):
        out.append(_ev(dev, ts, "dns_query", qname="%s.example" % _random_label(rng, 14)))
    return out, t0 + minutes * 60


def lateral_scan(rng, dev: Device, t0: float, minutes: float = 15) -> Tuple[List[Event], float]:
    """Internal service discovery from a compromised controller."""
    out: List[Event] = []
    ports = [22, 23, 80, 443, 502, 1883, 8080, 47808]
    for ts in np.sort(rng.uniform(t0, t0 + minutes * 60, int(25 * minutes))):
        dst = "10.20.%d.%d" % (rng.integers(0, 10), rng.integers(1, 255))
        out.append(_flow(dev, ts, dst, int(rng.choice(ports)), "tcp",
                         rng.uniform(60, 120), rng.uniform(0, 60), allowlisted=False))
    return out, t0 + minutes * 60


def rogue_firmware(rng, dev: Device, t0: float, minutes: float = 10) -> Tuple[List[Event], float]:
    """Unsigned firmware pushed from an attacker host, followed by a reboot."""
    out: List[Event] = [
        _ev(dev, t0, "fw_update", fw_version="9.9.9-x", fw_source="203.0.113.99",
            fw_signed="false", bytes_in=int(rng.uniform(3e6, 5e6))),
        _ev(dev, t0 + 30, "config_change", account="system", setting="remote_unlock"),
        _ev(dev, t0 + 90, "mqtt_connect", outcome="success", account=dev.device_id,
            client_id=dev.device_id),
        _ev(dev, t0 + 90.2, "mqtt_subscribe", topic=dev.topic("cmd")),
    ]
    return out, t0 + minutes * 60


# --------------------------------------------------------------------------
# Benign but unusual activity (category = "benign")
# --------------------------------------------------------------------------

def firmware_rollout(rng, devs: List[Device], t0: float, minutes: float = 30) -> Tuple[List[Event], float]:
    """Vendor-signed update pushed to every camera; large downloads from a new CDN edge."""
    out: List[Event] = []
    for i, dev in enumerate(devs):
        ts = t0 + i * (minutes * 60 / max(1, len(devs)))
        out.append(_ev(dev, ts, "dns_query", qname=dev.fw_domain))
        out.append(_flow(dev, ts + 1, str(rng.choice(CAMERA_CDN_POOL)), 443, "tcp",
                         rng.uniform(5e3, 1e4), rng.uniform(4e7, 6e7)))
        out.append(_ev(dev, ts + 60, "fw_update", fw_version="4.2.1", fw_source=dev.fw_domain,
                       fw_signed="true", bytes_in=int(rng.uniform(4e7, 6e7))))
        out.append(_ev(dev, ts + 180, "mqtt_connect", outcome="success",
                       account=dev.device_id, client_id=dev.device_id))
        out.append(_ev(dev, ts + 180.2, "mqtt_subscribe", topic=dev.topic("cmd")))
    return out, t0 + minutes * 60


def maintenance(rng, dev: Device, t0: float, minutes: float = 45) -> Tuple[List[Event], float]:
    """A technician logs in (one typo) and changes several settings."""
    out: List[Event] = [
        _ev(dev, t0, "device_auth", service="ssh", outcome="failure",
            account="facility-admin", src_ip=ADMIN_WORKSTATION),
        _ev(dev, t0 + 15, "device_auth", service="ssh", outcome="success",
            account="facility-admin", src_ip=ADMIN_WORKSTATION),
    ]
    for k in range(6):
        out.append(_ev(dev, t0 + 300 + 360 * k, "config_change", account="facility-admin",
                       setting=str(rng.choice(["setpoint", "schedule", "fan_curve"]))))
    return out, t0 + minutes * 60


def broker_restart(rng, devs: List[Device], t0: float, minutes: float = 5) -> Tuple[List[Event], float]:
    """The MQTT broker restarts: every device retries, fails a few times, reconnects."""
    out: List[Event] = []
    for dev in devs:
        ts = t0 + rng.uniform(0, 30)
        for _ in range(int(rng.integers(1, 4))):
            out.append(_ev(dev, ts, "mqtt_connect", outcome="failure", reason="server_unavailable",
                           account=dev.device_id, client_id=dev.device_id))
            ts += rng.uniform(10, 25)
        out.append(_ev(dev, ts, "mqtt_connect", outcome="success",
                       account=dev.device_id, client_id=dev.device_id))
        out.append(_ev(dev, ts + 0.2, "mqtt_subscribe", topic=dev.topic("cmd")))
    return out, t0 + minutes * 60


# scenario -> (category, MITRE technique, signature rule expected to fire, description)
SCENARIOS: Dict[str, Tuple[str, str, str, str]] = {
    "telnet_bruteforce": ("attack", "T1110.001", "100602",
                          "Mirai-style default-credential guessing on telnet, loader download, outbound scanning"),
    "lowslow_bruteforce": ("attack", "T1110.001", "none",
                           "SSH password guessing at ~15 attempts/hour from rotating addresses"),
    "mqtt_recon": ("attack", "T1110.001, T1040", "100604",
                   "Broker account guessing, then wildcard subscriptions to read all topics"),
    "exfiltration": ("attack", "T1048", "none",
                     "Bulk HTTPS upload of recordings to an unknown external host"),
    "c2_beaconing": ("attack", "T1071.001, T1568.002", "none",
                     "60-second check-ins to a C2 server plus DGA-style DNS lookups"),
    "lateral_scan": ("attack", "T1046", "100608",
                     "Internal service discovery across the building network"),
    "rogue_firmware": ("attack", "T1542.001", "100606",
                       "Unsigned firmware from an attacker host, settings changed, reboot"),
    "firmware_rollout": ("benign", "-", "100605",
                         "Vendor-signed firmware update on all cameras (large downloads, reboots)"),
    "maintenance": ("benign", "-", "100603",
                    "Technician SSH session with one typo and several configuration changes"),
    "broker_restart": ("benign", "-", "none",
                       "MQTT broker restart: every device fails to connect, then reconnects"),
}

SINGLE_DEVICE: Dict[str, Callable] = {
    "telnet_bruteforce": telnet_bruteforce, "lowslow_bruteforce": lowslow_bruteforce,
    "mqtt_recon": mqtt_recon, "exfiltration": exfiltration, "c2_beaconing": c2_beaconing,
    "lateral_scan": lateral_scan, "rogue_firmware": rogue_firmware, "maintenance": maintenance,
}
MULTI_DEVICE: Dict[str, Callable] = {"firmware_rollout": firmware_rollout,
                                     "broker_restart": broker_restart}

# (scenario, target, start offset in hours from the start of the day, duration minutes)
TEST_DAY_SCHEDULE: List[Tuple[str, str, float, float]] = [
    ("telnet_bruteforce", "cam-02", 2 + 10 / 60, 30),
    ("rogue_firmware", "lock-02", 3.5, 10),
    ("lowslow_bruteforce", "hvac-03", 9.0, 240),
    ("maintenance", "hvac-01", 10.0, 45),
    ("mqtt_recon", "sens-07", 11 + 20 / 60, 15),
    ("firmware_rollout", "camera", 14.0, 30),
    ("exfiltration", "cam-04", 15 + 10 / 60, 35),
    ("broker_restart", "all", 16.5, 5),
    ("c2_beaconing", "sens-03", 17.0, 300),
    ("lateral_scan", "hvac-02", 20.25, 15),
]

# Two compressed hours for the live Wazuh demonstration (offsets in minutes).
DEMO_SCHEDULE: List[Tuple[str, str, float, float]] = [
    ("telnet_bruteforce", "cam-02", 10, 10),
    ("exfiltration", "cam-04", 30, 15),
    ("firmware_rollout", "camera", 50, 15),
    ("c2_beaconing", "sens-03", 65, 40),
    ("mqtt_recon", "sens-07", 80, 10),
    ("lateral_scan", "hvac-02", 95, 10),
]


def _run_schedule(schedule, fleet: List[Device], day_start: float, seed: int,
                  offset_unit: float) -> Tuple[List[Event], List[Incident]]:
    events: List[Event] = []
    incidents: List[Incident] = []
    index = fleet_index(fleet)
    for n, (scenario, target, offset, minutes) in enumerate(schedule, 1):
        rng = np.random.default_rng([seed, 1000 + n])
        t0 = day_start + offset * offset_unit
        category, mitre, rule, description = SCENARIOS[scenario]
        if scenario in MULTI_DEVICE:
            devs = fleet if target == "all" else [d for d in fleet if d.device_type == target]
            produced, t_end = MULTI_DEVICE[scenario](rng, devs, t0, minutes)
            targets = [d.device_id for d in devs]
        else:
            produced, t_end = SINGLE_DEVICE[scenario](rng, index[target], t0, minutes)
            targets = [target]
        events.extend(produced)
        for device_id in targets:
            incidents.append(Incident(
                "%s-%02d" % ("A" if category == "attack" else "B", n), category, scenario,
                device_id, pd.Timestamp(t0, unit="s", tz="UTC"),
                pd.Timestamp(t_end, unit="s", tz="UTC"), mitre, rule, description))
    return events, incidents


def simulate(days: int = 6, start: pd.Timestamp = DEFAULT_START, seed: int = 7,
             attack_day: Optional[int] = 5,
             fleet: Optional[List[Device]] = None) -> Tuple[List[Event], List[Incident]]:
    """Generate `days` of gateway events; scripted incidents happen on `attack_day`."""
    fleet = fleet or build_fleet()
    t_start = start.timestamp()
    events: List[Event] = []
    for day in range(days):
        d0 = t_start + day * DAY
        for i, dev in enumerate(fleet):
            events.extend(normal_traffic(np.random.default_rng([seed, i, day]), dev, d0, d0 + DAY))
    incidents: List[Incident] = []
    if attack_day is not None and 0 <= attack_day < days:
        produced, incidents = _run_schedule(TEST_DAY_SCHEDULE, fleet,
                                            t_start + attack_day * DAY, seed, HOUR)
        events.extend(produced)
    events.sort(key=lambda e: e["ts"])  # type: ignore[arg-type, return-value]
    return events, incidents


def simulate_demo(start: pd.Timestamp, minutes: float = 120, seed: int = 11,
                  fleet: Optional[List[Device]] = None,
                  with_incidents: bool = True) -> Tuple[List[Event], List[Incident]]:
    """A short live-demo stream: normal traffic for every device plus DEMO_SCHEDULE."""
    fleet = fleet or build_fleet()
    t0 = start.timestamp()
    t1 = t0 + minutes * 60
    events: List[Event] = []
    for i, dev in enumerate(fleet):
        events.extend(normal_traffic(np.random.default_rng([seed, i, 99]), dev, t0, t1))
    incidents: List[Incident] = []
    if with_incidents:
        schedule = [s for s in DEMO_SCHEDULE if s[2] + s[3] <= minutes]
        produced, incidents = _run_schedule(schedule, fleet, t0, seed, 60.0)
        events.extend(e for e in produced if float(e["ts"]) < t1)  # type: ignore[arg-type]
    events.sort(key=lambda e: e["ts"])  # type: ignore[arg-type, return-value]
    return events, incidents


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------

def iso(ts: float) -> str:
    return pd.Timestamp(ts, unit="s", tz="UTC").strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_json_line(event: Event) -> str:
    record = dict(event)
    record["ts"] = iso(float(event["ts"]))  # type: ignore[arg-type]
    return json.dumps(record, separators=(",", ":"))


def write_jsonl(events: Iterable[Event], path: Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(to_json_line(event) + "\n")
            n += 1
    return n


def incidents_frame(incidents: List[Incident]) -> pd.DataFrame:
    columns = ["incident_id", "category", "scenario", "device_id", "start", "end",
               "mitre", "signature_rule", "description"]
    frame = pd.DataFrame([i.as_row() for i in incidents], columns=columns)
    frame["start"] = pd.to_datetime(frame["start"], utc=True)
    frame["end"] = pd.to_datetime(frame["end"], utc=True)
    return frame
