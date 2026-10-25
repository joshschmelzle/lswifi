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
lswifi.backends.macos
~~~~~~~~~~~~~~~~~~~~~

CoreWLAN backend via PyObjC (pyobjc-framework-CoreWLAN, installed with lswifi on macOS).

CoreWLAN is imported lazily by MacOSBackend so this module, and the mapping
functions in it, import on any OS.

macOS 14+ only returns SSID, BSSID, country code and the IE blob when the
calling process holds a Location Services grant. Without it, scan results
still carry RSSI, channel and beacon interval, so rows are kept and the user
is told once why the other columns are blank. sudo does not change this.
"""

import json
import logging
from typing import Any

from lswifi.backends.base import (
    BackendError,
    BackendUnavailableError,
    BssRecord,
    InterfaceInfo,
    RecordScanSession,
)
from lswifi.helpers import (
    format_mbps,
    get_2ghz5ghz_frequency_from_channel_number,
    get_6ghz_frequency_from_channel_number,
)

log = logging.getLogger(__name__)

# CWChannelBand and CWChannelWidth, as in the macOS 26 SDK (PyObjC 12)
CW_CHANNEL_BAND_2GHZ = 1
CW_CHANNEL_BAND_5GHZ = 2
CW_CHANNEL_BAND_6GHZ = 3
CW_CHANNEL_WIDTH_MHZ = {1: 20, 2: 40, 3: 80, 4: 160}
BAND_NAMES = {
    CW_CHANNEL_BAND_2GHZ: "2.4 GHz",
    CW_CHANNEL_BAND_5GHZ: "5 GHz",
    CW_CHANNEL_BAND_6GHZ: "6 GHz",
}
CW_PHY_MODE_NAMES = {
    0: "none",
    1: "802.11a",
    2: "802.11b",
    3: "802.11g",
    4: "802.11n",
    5: "802.11ac",
    6: "802.11ax",
    7: "802.11be",
}
CW_INTERFACE_MODE_NAMES = {
    0: "none",
    1: "station",
    2: "IBSS",
    3: "Host AP",
}
# CWSecurity in CoreWLAN/CWTypes.h (kCWSecurityWPA3Personal is 11)
CW_SECURITY_NAMES = {
    0: "Open",
    1: "WEP",
    2: "WPA Personal",
    3: "WPA Personal Mixed",
    4: "WPA2 Personal",
    5: "Personal",
    6: "Dynamic WEP",
    7: "WPA Enterprise",
    8: "WPA Enterprise Mixed",
    9: "WPA2 Enterprise",
    10: "Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA3 Transition",
    14: "OWE",
    15: "OWE Transition",
}

UNSUPPORTED = "unsupported on macOS"

LOCATION_HELP = (
    "macOS hides SSID, BSSID, and information elements (security, width, "
    "amendments) from processes without a Location Services grant; showing "
    "RSSI and channel only. Grant Location Services to the app that runs "
    "lswifi in System Settings > Privacy & Security > Location Services. "
    "sudo does not help. See the macOS section of the README."
)

_location_warned = False


def warn_location_once() -> None:
    """Explain the Location Services redaction once per process"""
    global _location_warned
    if not _location_warned:
        _location_warned = True
        log.warning(LOCATION_HELP)


def frequency_from_channel(channel_number: int, band: int | None) -> int:
    """Center frequency in MHz for a CWChannel number and band; 0 if unknown"""
    if band == CW_CHANNEL_BAND_6GHZ:
        freq = get_6ghz_frequency_from_channel_number(str(channel_number))
    else:
        # 2.4 and 5 GHz channel numbers do not overlap
        freq = get_2ghz5ghz_frequency_from_channel_number(str(channel_number))
    return int(freq) if freq.isdigit() else 0


def _nsdata_bytes(data) -> bytes:
    return bytes(data) if data is not None else b""


def network_to_record(network, connected_bssid: str | None = None) -> BssRecord:
    """Map a CWNetwork (or anything shaped like one) to a BssRecord.

    Every location-gated accessor may return nil; that becomes an empty
    value, not an exception.
    """
    channel = network.wlanChannel()
    channel_number = channel.channelNumber() if channel is not None else 0
    band = channel.channelBand() if channel is not None else None
    width = channel.channelWidth() if channel is not None else None
    bssid = (network.bssid() or "").lower()
    rssi = network.rssiValue()
    return BssRecord(
        ssid=_nsdata_bytes(network.ssidData()),
        bssid=bssid,
        frequency_mhz=frequency_from_channel(channel_number, band),
        rssi_dbm=int(rssi) if rssi is not None else None,
        # documented as ms; observed values are the 802.11 TU field (100)
        beacon_interval_tu=int(network.beaconInterval() or 0),
        # no public source for the capability field; 0 means unknown here
        capability=0,
        ies=_nsdata_bytes(network.informationElementData()),
        phy_name=None,
        bss_type="Independent" if network.ibss() else "Infrastructure",
        rate_set=None,
        connected=bool(bssid) and bssid == connected_bssid,
        ie_source=None,
        channel_width_mhz=CW_CHANNEL_WIDTH_MHZ.get(width) if width else None,
    )


def is_redacted(record: BssRecord) -> bool:
    """Location Services withheld this record's identity and IEs"""
    return not record.bssid and not record.ies


def _responds(obj, selector: str) -> bool:
    checker = getattr(obj, "respondsToSelector_", None)
    if not callable(checker):
        return hasattr(obj, selector)
    try:
        import objc  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        query = selector
    else:
        try:
            query = objc.selector(None, selector=selector.encode(), signature=b"@@:@")
        except Exception:
            query = selector
    try:
        return bool(checker(query))
    except Exception:
        return False


def _call(obj, selector: str):
    if obj is None or not _responds(obj, selector):
        return None
    try:
        return getattr(obj, selector)()
    except Exception:
        return None


def _as_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _enum_name(value, names: dict):
    number = _as_int(value)
    if number is None:
        return None
    return names.get(number, number)


def _mapping_get(obj, key: str):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    getter = getattr(obj, "objectForKey_", None)
    if callable(getter):
        try:
            return getter(key)
        except Exception:
            return None
    try:
        return obj[key]
    except Exception:
        pass
    if _responds(obj, key):
        try:
            attr = getattr(obj, key)
            return attr() if callable(attr) else attr
        except Exception:
            return None
    return None


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except UnicodeDecodeError:
            return None
    text = str(value).strip()
    return text or None


def _monitor_value(monitor, selector: str):
    if monitor is None:
        return None
    if isinstance(monitor, dict):
        return monitor.get(selector)
    return _call(monitor, selector)


def _string_list(value) -> list[str]:
    if value is None or isinstance(value, (str, bytes)):
        text = _text(value)
        return [text] if text else []
    try:
        items = list(value)
    except Exception:
        return []
    found = []
    for item in items:
        text = _text(item)
        if text:
            found.append(text)
    return found


def _config_gateway(state) -> tuple[str | None, str | None]:
    ip = _text(_mapping_get(state, "ARPResolvedIPAddress"))
    hardware = _text(_mapping_get(state, "ARPResolvedHardwareAddress"))
    if hardware and ":" in hardware:
        hardware = hardware.lower()
    return ip, hardware


def _gateway(cw_iface) -> tuple[str | None, str | None]:
    monitor = _call(cw_iface, "ipMonitor")
    ip = hardware = None
    for selector in ("ipv4WiFiStateConfig", "ipv4StateConfig", "ipv4State"):
        state = _monitor_value(monitor, selector)
        if state is None:
            continue
        found_ip, found_mac = _config_gateway(state)
        if ip is None:
            ip = found_ip
        if hardware is None:
            hardware = found_mac
        if ip and hardware:
            break
    if not ip:
        ip = _text(_monitor_value(monitor, "ipv4Router"))
    return ip, hardware


def _ipv4_addresses(cw_iface) -> list[str]:
    return _string_list(_monitor_value(_call(cw_iface, "ipMonitor"), "ipv4Addresses"))


def _channel_runs(numbers: list[int]) -> list[list[int]]:
    ordered = sorted(set(numbers))
    if not ordered:
        return []
    if len(ordered) == 1:
        return [[ordered[0], ordered[0]]]
    step = min(b - a for a, b in zip(ordered, ordered[1:], strict=False) if b > a)
    runs: list[list[int]] = []
    start = previous = ordered[0]
    for number in ordered[1:]:
        if number - previous == step:
            previous = number
            continue
        runs.append([start, previous])
        start = previous = number
    runs.append([start, previous])
    return runs


def summarize_supported_channels(channels) -> list[dict] | None:
    """Per-band channel runs and widths from CWChannel objects"""
    if not channels:
        return None
    grouped: dict[int, dict] = {}
    for channel in channels:
        try:
            number = int(channel.channelNumber())
            band = int(channel.channelBand())
            width = channel.channelWidth()
        except Exception:
            continue
        slot = grouped.setdefault(band, {"numbers": [], "widths": []})
        slot["numbers"].append(number)
        if width:
            slot["widths"].append(width)
    if not grouped:
        return None
    preferred = (
        CW_CHANNEL_BAND_2GHZ,
        CW_CHANNEL_BAND_5GHZ,
        CW_CHANNEL_BAND_6GHZ,
    )
    order = [band for band in preferred if band in grouped]
    order.extend(sorted(band for band in grouped if band not in preferred))
    summary = []
    for band in order:
        slot = grouped[band]
        known = sorted(
            {
                CW_CHANNEL_WIDTH_MHZ[code]
                for code in set(slot["widths"])
                if code in CW_CHANNEL_WIDTH_MHZ
            }
        )
        unknown = sorted(
            int(code)
            for code in set(slot["widths"])
            if code not in CW_CHANNEL_WIDTH_MHZ
        )
        summary.append(
            {
                "band": BAND_NAMES.get(band, str(band)),
                "ranges": _channel_runs(slot["numbers"]),
                "widths_mhz": known + unknown,
            }
        )
    return summary


def format_supported_channels(summary: list[dict]) -> str:
    parts = []
    for band in summary:
        ranges = [
            str(start) if start == end else f"{start}-{end}"
            for start, end in band["ranges"]
        ]
        text = f"{band['band']} {', '.join(ranges)}"
        if band["widths_mhz"]:
            text += f" ({'/'.join(str(width) for width in band['widths_mhz'])})"
        parts.append(text)
    return ", ".join(parts)


def _interface_state(cw_iface) -> str:
    if not cw_iface.powerOn():
        return "powered off"
    # interfaceMode is kCWInterfaceModeNone (0) when not associated
    if cw_iface.interfaceMode():
        return "connected"
    return "disconnected"


class MacOSScanSession(RecordScanSession):
    redacted = False

    def to_bss(self, bss, record: BssRecord):
        if is_redacted(record):
            self.redacted = True
        # CWNetwork has no TSF, so there is no AP uptime to show
        bss.uptime.value = "--"
        if not record.ies:
            # nothing to decode; do not imply open security or 1 SS
            for attr in ("security", "auth", "encryption", "pmf", "spatial_streams"):
                getattr(bss, attr).value = "--"
        elif bss.security.value == "NONE":
            # no RSN/WPA IE and no capability field (no Privacy bit): open
            # or WEP. supportsSecurity: is not used: it answers whether a
            # profile could join, not what the BSS advertises (#101)
            for attr in ("security", "auth", "encryption"):
                getattr(bss, attr).value = "NONE?"
        return bss

    async def scan(self) -> None:
        self.redacted = False
        await super().scan()
        if self.redacted:
            warn_location_once()


class MacOSBackend:
    """CoreWLAN backend"""

    name = "macos"
    platform_name = "macOS"
    supports_events = True

    def __init__(self, corewlan: Any = None) -> None:
        if corewlan is None:
            try:
                import CoreWLAN as corewlan  # type: ignore[import-not-found,import-untyped,no-redef]
            except ImportError as error:
                raise BackendUnavailableError(
                    "CoreWLAN is not available to Python; reinstall lswifi "
                    "or run: pip install pyobjc-framework-CoreWLAN"
                ) from error
        self.corewlan = corewlan
        self.client = corewlan.CWWiFiClient.sharedWiFiClient()

    def _native(self, iface: InterfaceInfo):
        if iface.native is not None:
            return iface.native
        return self.client.interfaceWithName_(iface.connection_name)

    def list_interfaces(self) -> list[InterfaceInfo]:
        infos = []
        for cw_iface in self.client.interfaces() or []:
            name = str(cw_iface.interfaceName() or "")
            infos.append(
                InterfaceInfo(
                    connection_name=name,
                    description=f"Wi-Fi ({name})",
                    guid_string="",
                    mac=str(cw_iface.hardwareAddress() or "").lower(),
                    state_string=_interface_state(cw_iface),
                    native=cw_iface,
                )
            )
        return infos

    def _records(self, networks, cw_iface) -> list[BssRecord]:
        connected = (cw_iface.bssid() or "").lower() or None
        return [network_to_record(network, connected) for network in networks]

    def scan(self, iface: InterfaceInfo) -> list[BssRecord]:
        """Broadcast scan (nil SSID), blocking until CoreWLAN returns"""
        cw_iface = self._native(iface)
        networks, error = cw_iface.scanForNetworksWithSSID_error_(None, None)
        if networks is None:
            log.debug("scanForNetworksWithSSID failed: %s; using scan cache", error)
            networks = cw_iface.cachedScanResults()
            if networks is None:
                raise BackendError(
                    f"CoreWLAN scan failed on {iface.connection_name}: {error}"
                )
        elif error is not None:
            # observed: kCWTimeoutErr (-3905) alongside a full result set
            log.debug("scanForNetworksWithSSID returned results and %s", error)
        return self._records(networks, cw_iface)

    def cached_scan(self, iface: InterfaceInfo) -> list[BssRecord]:
        """Read the interface scan cache without triggering a scan"""
        cw_iface = self._native(iface)
        networks = cw_iface.cachedScanResults()
        return self._records(networks or [], cw_iface)

    def open_session(self, args, iface: InterfaceInfo) -> MacOSScanSession:
        return MacOSScanSession(self, iface, args)

    def bus_info(self, iface: InterfaceInfo) -> tuple:
        return (None, None)

    def watch_events(self, args) -> None:
        """--watchevents: CoreWLAN events plus airportd log markers, until Ctrl-C"""
        from lswifi.backends.macos_events import MacOSEventWatcher

        interfaces = self.list_interfaces()
        if not interfaces:
            raise BackendError("no Wi-Fi interfaces found")
        MacOSEventWatcher(self.client, interfaces, args).run()

    def interface_info(self, args, iface: InterfaceInfo) -> str:
        """-ap, -channel, --get-interfaces from the associated CWInterface"""
        cw_iface = self._native(iface)
        if args.supported:
            return (
                f"    --supported: {UNSUPPORTED}\n"
                "    AP uptime isn't available on macOS\n"
            )
        bssid = (cw_iface.bssid() or "").lower()
        ssid = _nsdata_bytes(cw_iface.ssidData()).decode("utf-8", errors="replace")
        channel = cw_iface.wlanChannel()
        channel_number = channel.channelNumber() if channel is not None else None
        band = BAND_NAMES.get(channel.channelBand()) if channel is not None else None
        width = (
            CW_CHANNEL_WIDTH_MHZ.get(channel.channelWidth())
            if channel is not None
            else None
        )
        state = _interface_state(cw_iface)
        if state == "connected" and not bssid:
            warn_location_once()

        base = {"interface": iface.connection_name, "mac": iface.mac}
        if args.get_current_ap or args.get_current_channel:
            fields = {}
            if args.get_current_ap:
                fields["bssid"] = bssid
            if args.get_current_channel:
                fields["channel"] = channel_number
            if args.json:
                return json.dumps(base | fields, indent=args.json_indent)
            if args.raw:
                return ", ".join(str(value) for value in fields.values())
            return ", ".join(
                f"{key.upper()}: {value}"
                for key, value in (
                    {"interface": iface.connection_name, "mac": iface.mac} | fields
                ).items()
            )

        connected = state == "connected"
        channels = summarize_supported_channels(
            _call(cw_iface, "supportedWLANChannels")
        )
        # mcsIndex, numberOfSpatialStreams, maxNSSSupportedForAP, and ipMonitor
        # are undocumented CoreWLAN selectors. They answer on some macOS builds
        # and are absent from the public header, so a missing or failing selector
        # is skipped.
        gateway_ip, gateway_mac = _gateway(cw_iface) if connected else (None, None)
        ipv4_addresses = _ipv4_addresses(cw_iface) or None
        mcs_index = _as_int(_call(cw_iface, "mcsIndex")) if connected else None
        spatial_streams = (
            _as_int(_call(cw_iface, "numberOfSpatialStreams")) if connected else None
        )
        max_spatial_streams = (
            _as_int(_call(cw_iface, "maxNSSSupportedForAP")) if connected else None
        )
        info = base | {
            "description": iface.description,
            "state": state,
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel_number,
            "band": band,
            "width_mhz": width,
            "rssi": cw_iface.rssiValue() if connected else None,
            "noise": cw_iface.noiseMeasurement() if connected else None,
            "tx_rate_mbps": cw_iface.transmitRate() if connected else None,
            "tx_power_mw": cw_iface.transmitPower(),
            "phy_mode": (
                _enum_name(_call(cw_iface, "activePHYMode"), CW_PHY_MODE_NAMES)
                if connected
                else None
            ),
            "security": (
                _enum_name(_call(cw_iface, "security"), CW_SECURITY_NAMES)
                if connected
                else None
            ),
            "interface_mode": _enum_name(
                _call(cw_iface, "interfaceMode"), CW_INTERFACE_MODE_NAMES
            ),
            "power_on": bool(cw_iface.powerOn()),
            "service_active": (
                None
                if (service := _call(cw_iface, "serviceActive")) is None
                else bool(service)
            ),
            "supported_channels": channels,
            "mcs_index": mcs_index,
            "spatial_streams": spatial_streams,
            "max_spatial_streams": max_spatial_streams,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "ipv4_addresses": ipv4_addresses,
            "country_code": cw_iface.countryCode(),
            "bus": None,
        }
        if args.json:
            return json.dumps(info, indent=args.json_indent, default=str)
        outstr = f"Interface: {iface.connection_name} is {state}\n"
        outstr += f"    Description: {iface.description}\n"
        outstr += f"    MAC: {iface.mac}\n"
        outstr += f"    State: {state}\n"
        if connected:
            outstr += f"    SSID: {ssid}\n"
            outstr += f"    BSSID: {bssid}\n"
            if channel_number is not None:
                outstr += f"    Channel: {channel_number}\n"
            if band is not None:
                outstr += f"    Band: {band}\n"
            if width is not None:
                outstr += f"    Width: {width} MHz\n"
            if info["rssi"] is not None:
                outstr += f"    RSSI: {info['rssi']} dBm\n"
            if info["noise"] is not None:
                outstr += f"    Noise: {info['noise']} dBm\n"
            if info["tx_rate_mbps"] is not None:
                outstr += f"    Transmit (Tx) Rate: {format_mbps(info['tx_rate_mbps'])} Mbps\n"
            if info["phy_mode"] is not None:
                outstr += f"    PHY Mode: {info['phy_mode']}\n"
            if info["security"] is not None:
                outstr += f"    Security: {info['security']}\n"
            if info["mcs_index"] is not None:
                outstr += f"    MCS: {info['mcs_index']}\n"
            if info["spatial_streams"] is not None:
                outstr += f"    Spatial Streams: {info['spatial_streams']}\n"
            if info["max_spatial_streams"] is not None:
                outstr += f"    Max Spatial Streams: {info['max_spatial_streams']}\n"
            if info["gateway_ip"] is not None:
                outstr += f"    Gateway: {info['gateway_ip']}\n"
            if info["gateway_mac"] is not None:
                outstr += f"    Gateway MAC: {info['gateway_mac']}\n"
        if info["ipv4_addresses"]:
            outstr += f"    IPv4 Address: {', '.join(info['ipv4_addresses'])}\n"
        if info["tx_power_mw"] is not None:
            outstr += f"    Tx Power: {format_mbps(info['tx_power_mw'])} mW\n"
        if info["interface_mode"] is not None:
            outstr += f"    Interface Mode: {info['interface_mode']}\n"
        outstr += f"    Power: {'on' if info['power_on'] else 'off'}\n"
        if info["service_active"] is not None:
            outstr += (
                f"    Service Active: {'yes' if info['service_active'] else 'no'}\n"
            )
        if channels:
            outstr += f"    Supported Channels: {format_supported_channels(channels)}\n"
        if info["country_code"]:
            outstr += f"    Country Code: {info['country_code']}\n"
        return outstr
