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
lswifi.backends.linux
~~~~~~~~~~~~~~~~~~~~~

nl80211 backend over generic netlink (lswifi.backends.nl80211), stdlib only.

Scan results carry the raw information elements, so the same IE parsers as
Windows decode them. Triggering a scan needs CAP_NET_ADMIN (root); without
it the kernel's cached scan results are dumped instead and the user is told
once. Only managed (station) and P2P-client interfaces are listed; monitor
interfaces are skipped.

Nothing here opens a socket at import time, so the mapping functions are
tested on any OS with synthetic netlink attributes.
"""

import errno
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lswifi.backends import nl80211 as nl
from lswifi.backends.base import (
    BackendError,
    BackendUnavailableError,
    BssRecord,
    InterfaceInfo,
    RecordScanSession,
)
from lswifi.helpers import get_channel_number_from_frequency

log = logging.getLogger(__name__)

UNSUPPORTED = "unsupported on Linux"
SCAN_TIMEOUT = 30.0  # 6 GHz passive scans on every channel take a while
SYSFS_NET = "/sys/class/net"

PERMISSION_HELP = (
    "triggering a Wi-Fi scan needs root (CAP_NET_ADMIN); showing the kernel's "
    "cached scan results, which may be stale or incomplete. Run lswifi with "
    "sudo for a fresh scan."
)

STATION_IFTYPES = (nl.IFTYPE_STATION, nl.IFTYPE_P2P_CLIENT)

_permission_warned = False


def warn_permission_once() -> None:
    """Explain the cached-results fallback once per process"""
    global _permission_warned
    if not _permission_warned:
        _permission_warned = True
        log.warning(PERMISSION_HELP)


def band_name(frequency_mhz: int | None) -> str | None:
    if not frequency_mhz:
        return None
    if 2400 <= frequency_mhz < 2500:
        return "2.4 GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5 GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6 GHz"
    return None


def channel_number(frequency_mhz: int | None) -> int | None:
    if not frequency_mhz:
        return None
    channel = get_channel_number_from_frequency(str(frequency_mhz))
    return int(channel) if str(channel).isdigit() else None


def ssid_from_ies(ies: bytes) -> bytes:
    """The SSID element (ID 0) value, or b"" """
    offset = 0
    while offset + 2 <= len(ies):
        eid, length = ies[offset], ies[offset + 1]
        if offset + 2 + length > len(ies):
            break
        if eid == 0:
            return bytes(ies[offset + 2 : offset + 2 + length])
        offset += 2 + length
    return b""


def bss_to_record(attrs: dict[int, bytes]) -> BssRecord:
    """Map the attributes nested in NL80211_ATTR_BSS to a BssRecord.

    NL80211_BSS_INFORMATION_ELEMENTS holds the IEs of the latest frame (a
    probe response when NL80211_BSS_PRESP_DATA is set); BEACON_IES is only
    used when there is nothing else.
    """
    ies = attrs.get(nl.BSS_INFORMATION_ELEMENTS)
    if ies:
        ie_source = "probe_response" if nl.BSS_PRESP_DATA in attrs else "beacon"
    elif attrs.get(nl.BSS_BEACON_IES):
        ies, ie_source = attrs[nl.BSS_BEACON_IES], "beacon"
    else:
        ies, ie_source = b"", None
    ies = bytes(ies)
    mbm = nl.get_int(attrs, nl.BSS_SIGNAL_MBM)
    capability = nl.get_uint(attrs, nl.BSS_CAPABILITY, 0) or 0
    status = nl.get_uint(attrs, nl.BSS_STATUS)
    tsf = nl.get_uint(attrs, nl.BSS_TSF)
    if tsf is None:
        tsf = nl.get_uint(attrs, nl.BSS_BEACON_TSF, 0)
    bss_type = "Infrastructure"
    if capability & 0x0002 and not capability & 0x0001:
        bss_type = "Independent"
    return BssRecord(
        ssid=ssid_from_ies(ies),
        bssid=nl.mac_str(attrs.get(nl.BSS_BSSID)),
        frequency_mhz=nl.get_uint(attrs, nl.BSS_FREQUENCY, 0) or 0,
        rssi_dbm=round(mbm / 100) if mbm is not None else None,
        link_quality=nl.get_uint(attrs, nl.BSS_SIGNAL_UNSPEC),
        beacon_interval_tu=nl.get_uint(attrs, nl.BSS_BEACON_INTERVAL, 100) or 100,
        tsf=tsf or 0,
        capability=capability,
        ies=ies,
        phy_name=None,
        bss_type=bss_type,
        rate_set=None,
        connected=status in (nl.BSS_STATUS_ASSOCIATED, nl.BSS_STATUS_IBSS_JOINED),
        ie_source=ie_source,
        channel_width_mhz=nl.BSS_CHAN_WIDTH_MHZ.get(
            nl.get_uint(attrs, nl.BSS_CHAN_WIDTH, 0) or 0
        ),
        seen_ms_ago=nl.get_uint(attrs, nl.BSS_SEEN_MS_AGO),
    )


@dataclass
class LinuxInterface:
    """What NL80211_CMD_GET_INTERFACE says about one netdev"""

    ifindex: int
    name: str
    wiphy: int | None = None
    iftype: int | None = None
    mac: str = ""
    ssid: bytes = b""
    frequency_mhz: int | None = None
    width_mhz: int | None = None
    center_freq1: int | None = None
    tx_power_mbm: int | None = None

    @property
    def is_station(self) -> bool:
        return self.iftype in STATION_IFTYPES


def interface_from_attrs(attrs: dict[int, bytes]) -> LinuxInterface | None:
    ifindex = nl.get_uint(attrs, nl.ATTR_IFINDEX)
    if ifindex is None:  # e.g. a P2P-device wdev with no netdev
        return None
    width = nl.get_uint(attrs, nl.ATTR_CHANNEL_WIDTH)
    return LinuxInterface(
        ifindex=ifindex,
        name=nl.get_str(attrs, nl.ATTR_IFNAME) or f"if{ifindex}",
        wiphy=nl.get_uint(attrs, nl.ATTR_WIPHY),
        iftype=nl.get_uint(attrs, nl.ATTR_IFTYPE),
        mac=nl.mac_str(attrs.get(nl.ATTR_MAC)),
        ssid=bytes(attrs.get(nl.ATTR_SSID, b"")),
        frequency_mhz=nl.get_uint(attrs, nl.ATTR_WIPHY_FREQ),
        width_mhz=nl.CHAN_WIDTH_MHZ.get(width) if width is not None else None,
        center_freq1=nl.get_uint(attrs, nl.ATTR_CENTER_FREQ1),
        tx_power_mbm=nl.get_uint(attrs, nl.ATTR_WIPHY_TX_POWER_LEVEL),
    )


@dataclass
class LinkInfo:
    """Current association, from GET_INTERFACE plus the AP's station entry"""

    connected: bool = False
    bssid: str | None = None
    ssid: bytes = b""
    frequency_mhz: int | None = None
    width_mhz: int | None = None
    rssi: int | None = None
    tx_rate_mbps: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ssid_text(self) -> str:
        return self.ssid.decode("utf-8", errors="replace")

    @property
    def channel(self) -> int | None:
        return channel_number(self.frequency_mhz)

    @property
    def band(self) -> str | None:
        return band_name(self.frequency_mhz)


def station_to_link(attrs: dict[int, bytes]) -> tuple[str, int | None, float | None]:
    """(bssid, signal dBm, tx bitrate Mbps) from a GET_STATION reply"""
    info = nl.parse_attrs(attrs.get(nl.ATTR_STA_INFO, b""))
    signal = nl.get_int(info, nl.STA_INFO_SIGNAL)
    rate = None
    tx = nl.parse_attrs(info.get(nl.STA_INFO_TX_BITRATE, b""))
    units = nl.get_uint(tx, nl.RATE_INFO_BITRATE32)
    if units is None:
        units = nl.get_uint(tx, nl.RATE_INFO_BITRATE)
    if units:
        rate = units / 10
    return nl.mac_str(attrs.get(nl.ATTR_MAC)), signal, rate


class Sysfs:
    """/sys/class/net reads; root is swappable for tests"""

    def __init__(self, root: str = SYSFS_NET) -> None:
        self.root = root

    def _read(self, *parts: str) -> str | None:
        try:
            with open(os.path.join(self.root, *parts)) as handle:
                return handle.read().strip()
        except OSError:
            return None

    def is_up(self, name: str) -> bool | None:
        flags = self._read(name, "flags")
        if flags is None:
            return None
        try:
            return bool(int(flags, 16) & 0x1)  # IFF_UP
        except ValueError:
            return None

    def driver(self, name: str) -> str | None:
        path = os.path.join(self.root, name, "device", "driver")
        try:
            return os.path.basename(os.path.realpath(path, strict=True))
        except OSError:
            return None

    def bus_info(self, name: str) -> tuple:
        """(bus type, detail) such as ("USB", "0e8d:7961 at 4-1:1.0")"""
        device = os.path.join(self.root, name, "device")
        try:
            real = os.path.realpath(device, strict=True)
            subsystem = os.path.basename(
                os.path.realpath(os.path.join(device, "subsystem"), strict=True)
            )
        except OSError:
            return (None, None)
        where = os.path.basename(real)
        if subsystem == "usb":
            parent = os.path.dirname(real)
            ids = [
                self._read_path(os.path.join(parent, f))
                for f in ("idVendor", "idProduct")
            ]
            if all(ids):
                return ("USB", f"{ids[0]}:{ids[1]} at {where}")
            return ("USB", where)
        if subsystem == "pci":
            ids = [self._read_path(os.path.join(real, f)) for f in ("vendor", "device")]
            if all(ids):
                return ("PCI", f"{ids[0]}:{ids[1]} at {where}".replace("0x", ""))
            return ("PCI", where)
        return (subsystem.upper(), where)

    @staticmethod
    def _read_path(path: str) -> str | None:
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            return None


def _state(native: LinuxInterface, up: bool | None) -> str:
    if up is False:
        return "down"
    return "connected" if native.ssid else "disconnected"


class LinuxScanSession(RecordScanSession):
    async def scan(self) -> None:
        try:
            await super().scan()
        except BackendError as error:
            # the app runs sessions in worker threads and drops exceptions;
            # say what went wrong instead of only "no scan data"
            log.error("%s", error)
            self.data = None
            self.scan_finished = True


class LinuxBackend:
    """nl80211 backend"""

    name = "linux"
    platform_name = "Linux"
    supports_events = True

    def __init__(
        self,
        netlink: Callable[[], nl.GenericNetlink] | None = None,
        sysfs: Sysfs | None = None,
        scan_timeout: float = SCAN_TIMEOUT,
    ) -> None:
        self._netlink = netlink or nl.GenericNetlink
        self.sysfs = sysfs or Sysfs()
        self.scan_timeout = scan_timeout
        self._six_ghz: dict[int, bool] = {}
        try:
            self.netlink().close()
        except OSError as error:
            raise BackendUnavailableError(
                f"nl80211 is not available ({error.strerror or error}); "
                "is there a Wi-Fi adapter with a cfg80211 driver?"
            ) from error

    def netlink(self) -> nl.GenericNetlink:
        """A fresh nl80211 socket; one per operation keeps threads apart"""
        return self._netlink()

    # --- interfaces -------------------------------------------------------

    def _interfaces(self) -> list[LinuxInterface]:
        with self.netlink() as sock:
            replies = sock.request(nl.CMD_GET_INTERFACE, dump=True)
        found = [interface_from_attrs(reply.attrs) for reply in replies]
        return sorted((i for i in found if i is not None), key=lambda i: i.name)

    def _info(self, native: LinuxInterface) -> InterfaceInfo:
        driver = self.sysfs.driver(native.name)
        phy = f"phy{native.wiphy}" if native.wiphy is not None else "phy?"
        description = f"{driver} ({phy})" if driver else f"Wi-Fi ({phy})"
        return InterfaceInfo(
            connection_name=native.name,
            description=description,
            guid_string="",
            mac=native.mac,
            state_string=_state(native, self.sysfs.is_up(native.name)),
            native=native,
        )

    def list_interfaces(self) -> list[InterfaceInfo]:
        """Station interfaces only; monitor, AP and P2P-device are skipped"""
        infos = []
        for native in self._interfaces():
            if native.is_station:
                infos.append(self._info(native))
            else:
                log.debug(
                    "skipping %s (%s)",
                    native.name,
                    nl.IFTYPE_NAMES.get(native.iftype or 0, native.iftype),
                )
        return infos

    def _native(self, iface: InterfaceInfo) -> LinuxInterface:
        if isinstance(iface.native, LinuxInterface):
            return iface.native
        for native in self._interfaces():
            if native.name == iface.connection_name:
                return native
        raise BackendError(f"no nl80211 interface named {iface.connection_name}")

    def refresh(self, native: LinuxInterface) -> LinuxInterface:
        with self.netlink() as sock:
            replies = sock.request(
                nl.CMD_GET_INTERFACE, nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex)
            )
        for reply in replies:
            fresh = interface_from_attrs(reply.attrs)
            if fresh is not None:
                return fresh
        return native

    def link(self, native: LinuxInterface) -> LinkInfo:
        """Current SSID, BSSID, channel, RSSI and Tx rate"""
        native = self.refresh(native)
        if self.sysfs.is_up(native.name) is False:
            # some drivers (brcmfmac) keep reporting the last channel while down
            return LinkInfo(connected=False)
        info = LinkInfo(
            connected=bool(native.ssid),
            ssid=native.ssid,
            frequency_mhz=native.frequency_mhz,
            width_mhz=native.width_mhz,
        )
        if not info.connected:
            return info
        try:
            with self.netlink() as sock:
                stations = sock.request(
                    nl.CMD_GET_STATION,
                    nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex),
                    dump=True,
                )
        except OSError as error:
            log.debug("GET_STATION on %s failed: %s", native.name, error)
            stations = []
        for station in stations:
            bssid, signal, rate = station_to_link(station.attrs)
            if bssid:
                info.bssid, info.rssi, info.tx_rate_mbps = bssid, signal, rate
                break
        return info

    def country_code(self) -> str | None:
        try:
            with self.netlink() as sock:
                replies = sock.request(nl.CMD_GET_REG)
        except OSError as error:
            log.debug("GET_REG failed: %s", error)
            return None
        for reply in replies:
            alpha2 = nl.get_str(reply.attrs, nl.ATTR_REG_ALPHA2)
            if alpha2:
                return alpha2
        return None

    # --- scanning ---------------------------------------------------------

    def supports_6ghz(self, native: LinuxInterface) -> bool:
        """Whether the interface's wiphy lists a 6 GHz band"""
        if native.wiphy is None:
            return False
        if native.wiphy in self._six_ghz:
            return self._six_ghz[native.wiphy]
        supported = False
        try:
            with self.netlink() as sock:
                replies = sock.request(
                    nl.CMD_GET_WIPHY,
                    nl.attr_u32(nl.ATTR_WIPHY, native.wiphy)
                    + nl.attr_flag(nl.ATTR_SPLIT_WIPHY_DUMP),
                    dump=True,
                )
        except OSError as error:
            log.debug("GET_WIPHY for phy%s failed: %s", native.wiphy, error)
            replies = []
        for reply in replies:
            if nl.get_uint(reply.attrs, nl.ATTR_WIPHY) != native.wiphy:
                continue
            bands = reply.attrs.get(nl.ATTR_WIPHY_BANDS)
            if bands and nl.BAND_6GHZ in nl.parse_attrs(bands):
                supported = True
        log.debug("phy%s 6 GHz support: %s", native.wiphy, supported)
        self._six_ghz[native.wiphy] = supported
        return supported

    def trigger_scan(self, native: LinuxInterface) -> bool:
        """Trigger a wildcard active scan and wait for it to finish.

        False when no fresh results are coming: no permission, aborted, or
        timed out. Passive-only channels (6 GHz no-IR, DFS) are still
        scanned passively by the driver.
        """
        with self.netlink() as events:
            events.join(nl.MCAST_GROUP_SCAN)
            request = nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex) + nl.pack_nested(
                nl.ATTR_SCAN_SSIDS,
                [nl.pack_attr(1, b"")],  # wildcard SSID
            )
            colocated = self.supports_6ghz(native)
            if native.ssid:
                log.info(
                    "%s is associated; the scan may briefly pause its traffic",
                    native.name,
                )
            # drop results of scans that finished before ours was requested
            while events.events(0):
                pass
            busy = False
            try:
                try:
                    self._request_scan(native, request, colocated)
                except nl.NetlinkError as error:
                    if not colocated or error.errno not in (
                        errno.EINVAL,
                        errno.EOPNOTSUPP,
                    ):
                        raise
                    log.debug(
                        "%s: colocated 6 GHz scan flag rejected (%s); retrying without",
                        native.name,
                        error.strerror,
                    )
                    if native.wiphy is not None:
                        self._six_ghz[native.wiphy] = False
                    self._request_scan(native, request, False)
            except nl.NetlinkError as error:
                if error.errno in (errno.EPERM, errno.EACCES):
                    warn_permission_once()
                    return False
                if error.errno == errno.ENETDOWN:
                    raise BackendError(
                        f"{native.name} is down; bring it up first "
                        f"(sudo ip link set {native.name} up)"
                    ) from error
                if error.errno != errno.EBUSY:
                    raise BackendError(
                        f"scan request failed on {native.name}: {error.strerror}"
                    ) from error
                # another scan (wpa_supplicant, NetworkManager) is running;
                # its results are just as fresh
                log.debug("%s: scan already in progress; waiting for it", native.name)
                busy = True
            # results count only after the kernel announces our scan started
            # (TRIGGER_SCAN event); a busy scan has already started
            started = busy
            deadline = time.monotonic() + self.scan_timeout
            while (remaining := deadline - time.monotonic()) > 0:
                for message in events.events(remaining):
                    if nl.get_uint(message.attrs, nl.ATTR_IFINDEX) != native.ifindex:
                        continue
                    if message.cmd == nl.CMD_TRIGGER_SCAN:
                        started = True
                    if not started:
                        continue
                    if message.cmd == nl.CMD_NEW_SCAN_RESULTS:
                        return True
                    if message.cmd == nl.CMD_SCAN_ABORTED:
                        log.warning(
                            "scan aborted on %s; showing cached results", native.name
                        )
                        return False
        log.warning(
            "scan on %s did not finish within %gs; showing cached results",
            native.name,
            self.scan_timeout,
        )
        return False

    def _request_scan(
        self, native: LinuxInterface, request: bytes, colocated: bool
    ) -> None:
        if colocated:
            # also probe 6 GHz APs advertised in RNRs on 2.4/5 GHz
            request += nl.attr_u32(nl.ATTR_SCAN_FLAGS, nl.SCAN_FLAG_COLOCATED_6GHZ)
        with self.netlink() as sock:
            sock.request(nl.CMD_TRIGGER_SCAN, request)

    def dump_scan(self, native: LinuxInterface) -> list[BssRecord]:
        """The kernel's scan results for this interface; no privileges needed"""
        try:
            with self.netlink() as sock:
                replies = sock.request(
                    nl.CMD_GET_SCAN,
                    nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex),
                    dump=True,
                )
        except OSError as error:
            raise BackendError(
                f"reading scan results failed on {native.name}: {error.strerror or error}"
            ) from error
        return [
            bss_to_record(nl.parse_attrs(reply.attrs[nl.ATTR_BSS]))
            for reply in replies
            if nl.ATTR_BSS in reply.attrs
        ]

    def scan(self, iface: InterfaceInfo) -> list[BssRecord]:
        """Fresh scan when permitted, else the cached results"""
        native = self._native(iface)
        if self.sysfs.is_up(native.name) is False:
            # a down interface has no scan cache either; say why up front
            raise BackendError(
                f"{native.name} is down; bring it up first "
                f"(sudo ip link set {native.name} up)"
            )
        fresh = self.trigger_scan(native)
        records = self.dump_scan(native)
        if not fresh and not records:
            log.warning(
                "%s: the kernel has no cached scan results (nothing has scanned "
                "recently); run lswifi with sudo to scan, or fill the cache with "
                "'nmcli device wifi rescan'",
                native.name,
            )
        elif not fresh:
            ages = [r.seen_ms_ago for r in records if r.seen_ms_ago is not None]
            if ages:
                log.info(
                    "%s: %d cached BSSs, last seen %.0f-%.0f s ago",
                    native.name,
                    len(records),
                    min(ages) / 1000,
                    max(ages) / 1000,
                )
        return records

    def cached_scan(self, iface: InterfaceInfo) -> list[BssRecord]:
        return self.dump_scan(self._native(iface))

    def open_session(self, args, iface: InterfaceInfo) -> LinuxScanSession:
        return LinuxScanSession(self, iface, args)

    def bus_info(self, iface: InterfaceInfo) -> tuple:
        return self.sysfs.bus_info(iface.connection_name)

    def watch_events(self, args) -> None:
        """--watchevents: nl80211 mlme and scan multicast events, until Ctrl-C"""
        from lswifi.backends.linux_events import LinuxEventWatcher

        interfaces = self.list_interfaces()
        if not interfaces:
            raise BackendError("no Wi-Fi interfaces found")
        LinuxEventWatcher(self, interfaces, args).run()

    # --- -ap, -channel, --get-interfaces ----------------------------------

    def interface_info(self, args, iface: InterfaceInfo) -> str:
        """-ap, -channel, --get-interfaces from nl80211 and sysfs"""
        native = self._native(iface)
        if args.supported:
            return f"    --supported: {UNSUPPORTED}\n"
        link = self.link(native)
        up = self.sysfs.is_up(native.name)
        state = (
            "down" if up is False else "connected" if link.connected else "disconnected"
        )
        base = {"interface": iface.connection_name, "mac": iface.mac}
        if args.get_current_ap or args.get_current_channel:
            fields: dict[str, Any] = {}
            if args.get_current_ap:
                fields["bssid"] = link.bssid or ""
            if args.get_current_channel:
                fields["channel"] = link.channel
            if args.json:
                return json.dumps(base | fields, indent=args.json_indent)
            if args.raw:
                return ", ".join(str(value) for value in fields.values())
            return ", ".join(
                f"{key.upper()}: {value}" for key, value in (base | fields).items()
            )

        bus_type, bus = self.sysfs.bus_info(native.name)
        bus_text = f"{bus_type} {bus}" if bus_type else "unknown"
        tx_power = (
            native.tx_power_mbm / 100 if native.tx_power_mbm is not None else None
        )
        info = base | {
            "description": iface.description,
            "state": state,
            "ssid": link.ssid_text,
            "bssid": link.bssid,
            "channel": link.channel,
            "band": link.band,
            "width_mhz": link.width_mhz,
            "rssi": link.rssi,
            "tx_rate_mbps": link.tx_rate_mbps,
            "tx_power_dbm": tx_power,
            "country_code": self.country_code(),
            "bus": bus_text,
        }
        if args.json:
            return json.dumps(info, indent=args.json_indent, default=str)
        outstr = f"Interface: {iface.connection_name} is {state}\n"
        outstr += f"    Description: {iface.description}\n"
        outstr += f"    MAC: {iface.mac}\n"
        outstr += f"    Bus: {bus_text}\n"
        outstr += f"    State: {state}\n"
        if link.connected:
            outstr += f"    SSID: {link.ssid_text}\n"
            outstr += f"    BSSID: {link.bssid}\n"
            outstr += f"    Channel: {link.channel}\n"
            if link.band is not None:
                outstr += f"    Band: {link.band}\n"
            if link.width_mhz is not None:
                outstr += f"    Width: {link.width_mhz} MHz\n"
            outstr += f"    RSSI: {link.rssi} dBm\n"
            outstr += f"    Transmit (Tx) Rate: {link.tx_rate_mbps} Mbps\n"
        if tx_power is not None:
            outstr += f"    Transmit Power: {tx_power:g} dBm\n"
        if info["country_code"]:
            outstr += f"    Country Code: {info['country_code']}\n"
        return outstr
