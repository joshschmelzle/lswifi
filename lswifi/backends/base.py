#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

"""
lswifi.backends.base
~~~~~~~~~~~~~~~~~~~~

platform-neutral scan records and the backend protocol
"""

import datetime
import time
from dataclasses import dataclass
from typing import Any, Protocol


class BackendError(RuntimeError):
    """Base class for backend errors"""


class BackendNotImplementedError(BackendError):
    """No Wi-Fi backend exists for this platform yet"""


class BackendUnavailableError(BackendError):
    """The backend exists, but the OS service or library it needs is missing"""


@dataclass
class BssRecord:
    """One BSS from a scan, in units that do not depend on the OS API.

    Windows is the odd conversion: it reports frequency in kHz, so the
    Windows mapper divides by 1000 once.
    """

    ssid: bytes
    bssid: str  # aa:bb:cc:dd:ee:ff, lowercase
    frequency_mhz: int
    rssi_dbm: int | None = None
    link_quality: int | None = None  # Windows uLinkQuality, 0-100
    beacon_interval_tu: int = 100
    tsf: int = 0  # beacon/probe response timestamp field
    host_timestamp: int | None = None  # Windows ullHostTimestamp
    capability: int = 0  # 16-bit Capability Information field
    ies: bytes = b""  # TLV chain only: no fixed beacon fields, no FCS
    phy_name: str | None = None  # Windows DOT11_PHY_TYPE_DICT value
    bss_type: str | None = "Infrastructure"
    rate_set: list[int] | None = None  # raw WLAN_RATE_SET units
    connected: bool = False
    ie_source: str | None = None  # "beacon", "probe_response", or None
    phy_id: int | None = None  # Windows uPhyId
    in_reg_domain: bool | None = None  # Windows bInRegDomain
    raw: bytes | None = None  # backend-native record bytes (Windows WLAN_BSS_ENTRY)
    # width the OS reports, for when there are no IEs; IE-derived width wins
    channel_width_mhz: int | None = None
    seen_ms_ago: int | None = None  # Linux: since the kernel last heard the BSS


@dataclass
class InterfaceInfo:
    """A wireless interface as reported by a backend.

    Attribute names match lswifi.wlanapi.WirelessInterface so the output
    code can print either one.
    """

    connection_name: str
    description: str
    guid_string: str
    mac: str
    state_string: str
    native: Any = None  # backend-specific handle, e.g. WirelessInterface


class ScanSession(Protocol):
    """What lswifi.app needs from a per-interface scan session"""

    iface: Any
    mac: str
    data: list | None
    scan_finished: bool
    last_scan_time_iso: str

    async def scan(self) -> None: ...


class WifiBackend(Protocol):
    name: str
    supports_events: bool

    def list_interfaces(self) -> list[InterfaceInfo]: ...

    def scan(self, iface: InterfaceInfo) -> list[BssRecord]: ...

    def open_session(self, args, iface: InterfaceInfo) -> ScanSession: ...

    def interface_info(self, args, iface: InterfaceInfo) -> str: ...


class RecordScanSession:
    """ScanSession for backends whose scan() blocks and returns BssRecords.

    The Windows backend does not use this; it keeps its own notification
    driven client.
    """

    def __init__(self, backend: WifiBackend, iface: InterfaceInfo, args=None):
        self.backend = backend
        self.iface = iface
        self.mac = iface.mac
        self.args = args
        self.data: list | None = None
        self.scan_finished = False
        self.last_scan_time_iso = ""
        self.last_scan_time_epoch = 0.0

    async def scan(self) -> None:
        from lswifi.elements import WirelessNetworkBss

        self.scan_finished = False
        is_bytes_arg = bool(getattr(self.args, "bytes", None))
        records = self.backend.scan(self.iface)
        self.data = [
            self.to_bss(WirelessNetworkBss(record, is_bytes_arg=is_bytes_arg), record)
            for record in records
        ] or None
        now = datetime.datetime.now()
        self.last_scan_time_epoch = time.time()
        self.last_scan_time_iso = now.astimezone().isoformat(timespec="milliseconds")
        self.scan_finished = True

    def to_bss(self, bss, record: BssRecord):
        """Backend hook to adjust a parsed WirelessNetworkBss"""
        return bss
