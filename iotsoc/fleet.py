"""The simulated building: one IoT edge gateway and the devices behind it.

All addresses are reserved documentation / private ranges:
  10.20.0.0/16      building IoT network (RFC 1918)
  198.51.100.0/24   vendor clouds and CDNs (RFC 5737 TEST-NET-2)
  192.0.2.0/24      NTP pool (RFC 5737 TEST-NET-1)
  203.0.113.0/24    attacker infrastructure (RFC 5737 TEST-NET-3)
  198.18.0.0/15     background internet scanners (RFC 2544 benchmarking range)
Domain names use the reserved .example TLD (RFC 2606).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

GATEWAY_IP = "10.20.0.1"        # MQTT broker + firewall + DNS forwarder
NVR_IP = "10.20.9.10"           # video recorder (cameras stream here)
BMS_IP = "10.20.9.20"           # building management server (HVAC talks BACnet)
NTP_POOL = ["192.0.2.123", "192.0.2.124", "192.0.2.125", "192.0.2.126"]
NTP_DOMAIN = "pool.ntp.example"

VENDORS: Dict[str, Dict[str, object]] = {
    "camera": {"domain": "cloud.camvendor.example",
               "pool": ["198.51.100.%d" % i for i in range(10, 18)],
               "fw_domain": "fw.camvendor.example"},
    "sensor": {"domain": "api.sensevendor.example",
               "pool": ["198.51.100.%d" % i for i in range(30, 38)],
               "fw_domain": "fw.sensevendor.example"},
    "lock": {"domain": "hub.lockvendor.example",
             "pool": ["198.51.100.%d" % i for i in range(50, 58)],
             "fw_domain": "fw.lockvendor.example"},
    "hvac": {"domain": "portal.hvacvendor.example",
             "pool": ["198.51.100.%d" % i for i in range(70, 78)],
             "fw_domain": "fw.hvacvendor.example"},
}
# Cameras also pull thumbnails/updates through a CDN whose addresses rotate.
CAMERA_CDN_POOL = ["198.51.100.%d" % i for i in range(128, 255)]

BUSINESS_HOURS = (8, 18)  # UTC, [start, end)


@dataclass(frozen=True)
class Device:
    device_id: str
    device_type: str
    ip: str
    floor: int
    mgmt_service: Optional[str]          # "telnet", "ssh" or None
    internal_peers: Tuple[Tuple[str, int], ...]

    @property
    def vendor_domain(self) -> str:
        return str(VENDORS[self.device_type]["domain"])

    @property
    def vendor_pool(self) -> List[str]:
        return list(VENDORS[self.device_type]["pool"])  # type: ignore[arg-type]

    @property
    def fw_domain(self) -> str:
        return str(VENDORS[self.device_type]["fw_domain"])

    def topic(self, leaf: str) -> str:
        return "building/f%d/%s/%s/%s" % (self.floor, self.device_type, self.device_id, leaf)


def build_fleet() -> List[Device]:
    """20 devices: 10 sensors, 4 cameras, 3 smart locks, 3 HVAC controllers."""
    fleet: List[Device] = []
    for i in range(1, 11):
        fleet.append(Device("sens-%02d" % i, "sensor", "10.20.1.%d" % (10 + i),
                            floor=1 + (i - 1) // 2, mgmt_service=None, internal_peers=()))
    for i in range(1, 5):
        fleet.append(Device("cam-%02d" % i, "camera", "10.20.2.%d" % (10 + i),
                            floor=i, mgmt_service="telnet",
                            internal_peers=((NVR_IP, 554),)))
    for i in range(1, 4):
        fleet.append(Device("lock-%02d" % i, "lock", "10.20.3.%d" % (10 + i),
                            floor=i, mgmt_service=None, internal_peers=()))
    for i in range(1, 4):
        fleet.append(Device("hvac-%02d" % i, "hvac", "10.20.4.%d" % (10 + i),
                            floor=i, mgmt_service="ssh",
                            internal_peers=((BMS_IP, 47808),)))
    return fleet


def fleet_index(fleet: List[Device]) -> Dict[str, Device]:
    return {d.device_id: d for d in fleet}


def is_internal(ip: str) -> bool:
    return ip.startswith("10.")
