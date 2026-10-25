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
from lswifi.helpers import format_mbps, get_channel_number_from_frequency

log = logging.getLogger(__name__)

UNSUPPORTED = "unsupported on Linux"
IFF_UP = 0x1
WILDCARD_SSID = b""
SCAN_TIMEOUT = 30.0  # 6 GHz passive scans on every channel take a while
SYSFS_NET = "/sys/class/net"

PERMISSION_HELP = (
    "triggering a Wi-Fi scan needs root (CAP_NET_ADMIN); showing the kernel's "
    "cached scan results, which may be stale or incomplete. Run lswifi with "
    "sudo for a fresh scan."
)

STATION_IFTYPES = (nl.IFTYPE_STATION, nl.IFTYPE_P2P_CLIENT)

_permission_warned = False


def drop_queued_events(events: nl.GenericNetlink) -> None:
    while events.events(0):
        pass


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
    center_freq2: int | None = None
    tx_power_mbm: int | None = None
    links: list[dict[str, Any]] = field(default_factory=list)

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
        center_freq2=nl.get_uint(attrs, nl.ATTR_CENTER_FREQ2),
        tx_power_mbm=nl.get_uint(attrs, nl.ATTR_WIPHY_TX_POWER_LEVEL),
        links=parse_mlo_links(attrs, mac_field="addr"),
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


_HE_GI = {0: "0.8", 1: "1.6", 2: "3.2"}
_BAND_LABELS = {nl.BAND_2GHZ: "2.4 GHz", nl.BAND_5GHZ: "5 GHz", nl.BAND_6GHZ: "6 GHz"}
_BAND_ORDER = (nl.BAND_2GHZ, nl.BAND_5GHZ, nl.BAND_6GHZ)
_PHY_ORDER = ("HT", "VHT", "HE", "EHT")


def _uint(attrs: dict[int, bytes], kind: int) -> int | None:
    if kind not in attrs:
        return None
    return nl.get_uint(attrs, kind)


def _sint(attrs: dict[int, bytes], kind: int) -> int | None:
    if kind not in attrs:
        return None
    return nl.get_int(attrs, kind)


def _chains(payload: bytes | None) -> list[int] | None:
    if not payload:
        return None
    values = []
    for index, raw in sorted(nl.parse_attrs(payload).items()):
        value = nl.get_int({index: raw}, index)
        if value is not None:
            values.append(value)
    return values or None


def _he_gi(attrs: dict[int, bytes], kind: int) -> str | None:
    if kind not in attrs:
        return None
    code = nl.get_uint(attrs, kind)
    if code is None:
        return None
    return _HE_GI.get(code, str(code))


def _rate_width(attrs: dict[int, bytes]) -> int | str | None:
    if nl.RATE_INFO_320_MHZ_WIDTH in attrs:
        return 320
    if nl.RATE_INFO_160_MHZ_WIDTH in attrs:
        return 160
    if nl.RATE_INFO_80P80_MHZ_WIDTH in attrs:
        return "80+80"
    if nl.RATE_INFO_80_MHZ_WIDTH in attrs:
        return 80
    if nl.RATE_INFO_40_MHZ_WIDTH in attrs:
        return 40
    if nl.RATE_INFO_10_MHZ_WIDTH in attrs:
        return 10
    if nl.RATE_INFO_5_MHZ_WIDTH in attrs:
        return 5
    return None


def parse_rate(payload: bytes) -> dict[str, Any] | None:
    """NL80211_RATE_INFO_* to mbps plus the PHY fields the kernel actually sent.

    A legacy rate is only a bitrate. Width, MCS, NSS and GI stay unset, including
    GI 0 (0.8 µs), which is a real EHT/HE value.
    """
    attrs = nl.parse_attrs(payload)
    units = nl.get_uint(attrs, nl.RATE_INFO_BITRATE32)
    if units is None:
        units = nl.get_uint(attrs, nl.RATE_INFO_BITRATE)
    if not units:
        return None
    phy = mcs = nss = gi = None
    eht = (
        nl.RATE_INFO_EHT_MCS in attrs
        or nl.RATE_INFO_EHT_NSS in attrs
        or nl.RATE_INFO_EHT_GI in attrs
    )
    he = (
        nl.RATE_INFO_HE_MCS in attrs
        or nl.RATE_INFO_HE_NSS in attrs
        or nl.RATE_INFO_HE_GI in attrs
    )
    if eht:
        phy = "EHT"
        mcs = nl.get_uint(attrs, nl.RATE_INFO_EHT_MCS)
        nss = nl.get_uint(attrs, nl.RATE_INFO_EHT_NSS)
        gi = _he_gi(attrs, nl.RATE_INFO_EHT_GI)
    elif he:
        phy = "HE"
        mcs = nl.get_uint(attrs, nl.RATE_INFO_HE_MCS)
        nss = nl.get_uint(attrs, nl.RATE_INFO_HE_NSS)
        gi = _he_gi(attrs, nl.RATE_INFO_HE_GI)
    elif nl.RATE_INFO_VHT_MCS in attrs or nl.RATE_INFO_VHT_NSS in attrs:
        phy = "VHT"
        mcs = nl.get_uint(attrs, nl.RATE_INFO_VHT_MCS)
        nss = nl.get_uint(attrs, nl.RATE_INFO_VHT_NSS)
        gi = "0.4" if nl.RATE_INFO_SHORT_GI in attrs else "0.8"
    elif nl.RATE_INFO_MCS in attrs:
        phy = "HT"
        raw = nl.get_uint(attrs, nl.RATE_INFO_MCS)
        if raw is not None:
            mcs = raw % 8
            nss = raw // 8 + 1
        gi = "0.4" if nl.RATE_INFO_SHORT_GI in attrs else "0.8"
    return {
        "mbps": units / 10,
        "phy": phy,
        "mcs": mcs,
        "nss": nss,
        "width_mhz": _rate_width(attrs),
        "gi": gi,
    }


def format_rate(rate: dict[str, Any]) -> str:
    details = []
    if rate.get("phy"):
        details.append(str(rate["phy"]))
    if rate.get("mcs") is not None:
        details.append(f"MCS {rate['mcs']}")
    if rate.get("nss") is not None:
        details.append(f"NSS {rate['nss']}")
    if rate.get("width_mhz") is not None:
        details.append(f"{rate['width_mhz']} MHz")
    if rate.get("gi"):
        details.append(f"GI {rate['gi']}")
    text = f"{format_mbps(rate['mbps'])} Mbps"
    if details:
        text += ", " + ", ".join(details)
    return text


def parse_sta_info(payload: bytes) -> dict[str, Any]:
    """One STA_INFO nest. Missing attributes are omitted; explicit zeros stay."""
    attrs = nl.parse_attrs(payload)
    sta: dict[str, Any] = {}
    for key, kind in (
        ("inactive_time_ms", nl.STA_INFO_INACTIVE_TIME),
        ("rx_packets", nl.STA_INFO_RX_PACKETS),
        ("tx_packets", nl.STA_INFO_TX_PACKETS),
        ("tx_retries", nl.STA_INFO_TX_RETRIES),
        ("tx_failed", nl.STA_INFO_TX_FAILED),
        ("connected_time_s", nl.STA_INFO_CONNECTED_TIME),
        ("beacon_loss", nl.STA_INFO_BEACON_LOSS),
    ):
        value = _uint(attrs, kind)
        if value is not None:
            sta[key] = value
    for key, kind in (
        ("rx_duration_us", nl.STA_INFO_RX_DURATION),
        ("tx_duration_us", nl.STA_INFO_TX_DURATION),
    ):
        value = _uint(attrs, kind)
        if value:
            sta[key] = value
    rx_bytes = _uint(attrs, nl.STA_INFO_RX_BYTES64)
    if rx_bytes is None:
        rx_bytes = _uint(attrs, nl.STA_INFO_RX_BYTES)
    if rx_bytes is not None:
        sta["rx_bytes"] = rx_bytes
    tx_bytes = _uint(attrs, nl.STA_INFO_TX_BYTES64)
    if tx_bytes is None:
        tx_bytes = _uint(attrs, nl.STA_INFO_TX_BYTES)
    if tx_bytes is not None:
        sta["tx_bytes"] = tx_bytes
    for key, kind in (
        ("signal", nl.STA_INFO_SIGNAL),
        ("signal_avg", nl.STA_INFO_SIGNAL_AVG),
        ("beacon_signal_avg", nl.STA_INFO_BEACON_SIGNAL_AVG),
        ("ack_signal", nl.STA_INFO_ACK_SIGNAL),
        ("ack_signal_avg", nl.STA_INFO_ACK_SIGNAL_AVG),
    ):
        value = _sint(attrs, kind)
        if value is not None:
            sta[key] = value
    chains = _chains(attrs.get(nl.STA_INFO_CHAIN_SIGNAL))
    if chains:
        sta["signal_chains"] = chains
    chains_avg = _chains(attrs.get(nl.STA_INFO_CHAIN_SIGNAL_AVG))
    if chains_avg:
        sta["signal_avg_chains"] = chains_avg
    if nl.STA_INFO_TX_BITRATE in attrs:
        rate = parse_rate(attrs[nl.STA_INFO_TX_BITRATE])
        if rate:
            sta["tx_rate"] = rate
    if nl.STA_INFO_RX_BITRATE in attrs:
        rate = parse_rate(attrs[nl.STA_INFO_RX_BITRATE])
        if rate:
            sta["rx_rate"] = rate
    kbps = _uint(attrs, nl.STA_INFO_EXPECTED_THROUGHPUT)
    if kbps is not None:
        sta["expected_throughput_mbps"] = kbps / 1000
    return sta


def parse_mlo_links(
    attrs: dict[int, bytes], mac_field: str = "bssid"
) -> list[dict[str, Any]]:
    blob = attrs.get(nl.ATTR_MLO_LINKS)
    if not blob:
        return []
    links = []
    for _index, payload in nl.parse_attrs(blob).items():
        inner = nl.parse_attrs(payload)
        link: dict[str, Any] = {}
        if nl.ATTR_MLO_LINK_ID in inner:
            link["id"] = nl.get_uint(inner, nl.ATTR_MLO_LINK_ID)
        mac = nl.mac_str(inner.get(nl.ATTR_MAC))
        if mac:
            link[mac_field] = mac
        ap = nl.mac_str(inner.get(nl.ATTR_BSSID))
        if ap:
            link["bssid"] = ap
        if nl.ATTR_WIPHY_FREQ in inner:
            link["frequency_mhz"] = nl.get_uint(inner, nl.ATTR_WIPHY_FREQ)
        width = nl.get_uint(inner, nl.ATTR_CHANNEL_WIDTH)
        if width is not None and width in nl.CHAN_WIDTH_MHZ:
            link["width_mhz"] = nl.CHAN_WIDTH_MHZ[width]
        if nl.ATTR_CENTER_FREQ1 in inner:
            link["center_freq1_mhz"] = nl.get_uint(inner, nl.ATTR_CENTER_FREQ1)
        if nl.ATTR_CENTER_FREQ2 in inner:
            link["center_freq2_mhz"] = nl.get_uint(inner, nl.ATTR_CENTER_FREQ2)
        if nl.ATTR_WIPHY_TX_POWER_LEVEL in inner:
            link["tx_power_mbm"] = nl.get_uint(inner, nl.ATTR_WIPHY_TX_POWER_LEVEL)
        if nl.ATTR_STA_INFO in inner:
            link["station"] = parse_sta_info(inner[nl.ATTR_STA_INFO])
        if link:
            links.append(link)
    return links


def _merge_links(found: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    loose: list[dict[str, Any]] = []
    for link in found:
        ident = link.get("id")
        if ident is None:
            loose.append(link)
            continue
        if ident not in merged:
            merged[ident] = {}
            order.append(ident)
        current = merged[ident]
        for key, value in link.items():
            if key == "station":
                current.setdefault("station", value)
            elif key not in current or current[key] in (None, ""):
                current[key] = value
    return [merged[ident] for ident in order] + loose


def _public_link(link: dict[str, Any]) -> dict[str, Any]:
    public: dict[str, Any] = {}
    if link.get("id") is not None:
        public["id"] = link["id"]
    if link.get("addr"):
        public["addr"] = link["addr"]
    if link.get("bssid"):
        public["bssid"] = link["bssid"]
    freq = link.get("frequency_mhz")
    if freq is not None:
        public["frequency_mhz"] = freq
        number = channel_number(freq)
        if number is not None:
            public["channel"] = number
        band = band_name(freq)
        if band:
            public["band"] = band
    if link.get("width_mhz") is not None:
        public["width_mhz"] = link["width_mhz"]
    if link.get("center_freq1_mhz") is not None:
        public["center_freq1_mhz"] = link["center_freq1_mhz"]
    if link.get("center_freq2_mhz") is not None:
        public["center_freq2_mhz"] = link["center_freq2_mhz"]
    if link.get("tx_power_mbm") is not None:
        public["tx_power_dbm"] = link["tx_power_mbm"] / 100
    return public


def format_link(item: dict[str, Any]) -> str:
    bits = []
    if item.get("bssid"):
        bits.append(f"AP BSSID {item['bssid']}")
    if item.get("addr") and item.get("addr") != item.get("bssid"):
        bits.append(f"STA {item['addr']}")
    if item.get("channel") is not None:
        bits.append(f"channel {item['channel']}")
    if item.get("frequency_mhz") is not None:
        bits.append(f"{item['frequency_mhz']} MHz")
    if item.get("band"):
        bits.append(item["band"])
    if item.get("width_mhz") is not None:
        bits.append(f"{item['width_mhz']} MHz")
    if item.get("center_freq1_mhz") is not None:
        bits.append(f"center {item['center_freq1_mhz']} MHz")
    if item.get("center_freq2_mhz") is not None:
        bits.append(f"center2 {item['center_freq2_mhz']} MHz")
    if item.get("tx_power_dbm") is not None:
        bits.append(f"{format_mbps(item['tx_power_dbm'])} dBm")
    label = f"Link {item['id']}" if item.get("id") is not None else "Link"
    return f"{label}: {', '.join(bits)}"


def merge_station_dump(messages) -> tuple[str | None, dict[str, Any] | None, list]:
    """Fold a GET_STATION dump into one BSSID, MLD stats, and per-link identity.

    Top-level STA_INFO is the MLD aggregate. A dump that only nests STA_INFO
    under a single link uses that. Stats are not copied onto every link.
    """
    bssid = None
    aggregate = None
    found: list[dict[str, Any]] = []
    for message in messages:
        attrs = message.attrs
        mac = nl.mac_str(attrs.get(nl.ATTR_MAC))
        if mac and bssid is None:
            bssid = mac
        if nl.ATTR_STA_INFO in attrs:
            parsed = parse_sta_info(attrs[nl.ATTR_STA_INFO])
            if parsed and aggregate is None:
                aggregate = parsed
        found.extend(parse_mlo_links(attrs))
    links = _merge_links(found)
    if aggregate is None:
        nested = [link["station"] for link in links if link.get("station")]
        if len(nested) == 1:
            aggregate = nested[0]
    if bssid is None and len(links) == 1:
        bssid = links[0].get("bssid")
    return bssid, aggregate, links


def associated_mlo_links(messages) -> tuple[str | None, list[dict[str, Any]]]:
    mld = None
    found: list[dict[str, Any]] = []
    for message in messages:
        raw = message.attrs.get(nl.ATTR_BSS)
        if not raw:
            continue
        attrs = nl.parse_attrs(raw)
        if nl.get_uint(attrs, nl.BSS_STATUS) != nl.BSS_STATUS_ASSOCIATED:
            continue
        addr = nl.mac_str(attrs.get(nl.BSS_MLD_ADDR))
        if addr and mld is None:
            mld = addr
        link_id = nl.get_uint(attrs, nl.BSS_MLO_LINK_ID)
        if link_id is None:
            continue
        item: dict[str, Any] = {"id": link_id}
        bssid = nl.mac_str(attrs.get(nl.BSS_BSSID))
        if bssid:
            item["bssid"] = bssid
        freq = nl.get_uint(attrs, nl.BSS_FREQUENCY)
        if freq:
            item["frequency_mhz"] = freq
        found.append(item)
    return mld, found


def _local_addrs(links: list[dict[str, Any]]) -> dict[int, str]:
    found = {}
    for link in links:
        ident = link.get("id")
        addr = link.get("addr")
        if ident is not None and addr:
            found[ident] = addr
    return found


def _unlocal_bssid(link: dict[str, Any], local: dict[int, str]) -> dict[str, Any]:
    item = dict(link)
    ident = item.get("id")
    addr = local.get(ident) if isinstance(ident, int) else None
    if addr and item.get("bssid") == addr:
        item.pop("bssid", None)
        item.setdefault("addr", addr)
    return item


def _association(links: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not links:
        return None
    for item in links:
        if item.get("id") == 0:
            return item
    return links[0]


def _fill_from_link(
    links: list[dict[str, Any]],
    freq: int | None,
    width: int | None,
    center1: int | None,
    center2: int | None,
    tx_power: int | None,
) -> tuple[int | None, int | None, int | None, int | None, int | None]:
    chosen = _association(links)
    if not chosen:
        return freq, width, center1, center2, tx_power
    if freq is None:
        freq = chosen.get("frequency_mhz")
    if width is None:
        width = chosen.get("width_mhz")
    if center1 is None:
        center1 = chosen.get("center_freq1_mhz")
    if center2 is None:
        center2 = chosen.get("center_freq2_mhz")
    if tx_power is None:
        tx_power = chosen.get("tx_power_mbm")
    return freq, width, center1, center2, tx_power


def _drop_placeholder_mld_signal(station: dict[str, Any] | None, links: list) -> None:
    if not station or station.get("signal") != 0 or not links:
        return
    for link in links:
        if "signal" in (link.get("station") or {}):
            return
    station.pop("signal", None)


def station_to_link(attrs: dict[int, bytes]) -> tuple[str, int | None, float | None]:
    """(bssid, signal dBm, tx bitrate Mbps) from a GET_STATION reply"""
    info = parse_sta_info(attrs.get(nl.ATTR_STA_INFO, b""))
    tx = info.get("tx_rate") or {}
    return nl.mac_str(attrs.get(nl.ATTR_MAC)), info.get("signal"), tx.get("mbps")


def _step_runs(ordered: list[int], step: int) -> list[list[int]]:
    if not ordered:
        return []
    if len(ordered) == 1:
        return [[ordered[0], ordered[0]]]
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


def _on_raster(band: int, number: int) -> bool:
    residue = number % 4
    if band == nl.BAND_6GHZ:
        return residue == 1
    return residue in (0, 1)


def _break_around(
    start: int, end: int, step: int, blockers: list[int]
) -> list[list[int]]:
    channels = list(range(start, end + 1, step))
    pieces: list[list[int]] = []
    piece_start = previous = channels[0]
    for number in channels[1:]:
        if any(previous < block < number for block in blockers):
            pieces.append([piece_start, previous])
            piece_start = number
        previous = number
    pieces.append([piece_start, previous])
    return pieces


def _raster_runs(ordered: list[int], band: int) -> list[list[int]]:
    on = [number for number in ordered if _on_raster(band, number)]
    off = [number for number in ordered if not _on_raster(band, number)]
    runs: list[list[int]] = []
    for start, end in _step_runs(on, 4):
        runs.extend(_break_around(start, end, 4, off))
    runs.extend([[number, number] for number in off])
    runs.sort(key=lambda run: run[0])
    return runs


def _channel_runs(numbers: list[int], band: int | None = None) -> list[list[int]]:
    ordered = sorted(set(numbers))
    if not ordered:
        return []
    if band == nl.BAND_5GHZ or band == nl.BAND_6GHZ:
        return _raster_runs(ordered, band)
    if len(ordered) == 1:
        return [[ordered[0], ordered[0]]]
    step = min(b - a for a, b in zip(ordered, ordered[1:], strict=False) if b > a)
    return _step_runs(ordered, step)


def _range_text(ranges: list[list[int]]) -> str:
    return ", ".join(
        str(start) if start == end else f"{start}-{end}" for start, end in ranges
    )


def _freq_widths(attrs: dict[int, bytes], ht: bool, wide: bool, eht: bool) -> list[int]:
    widths = []
    if nl.FREQ_ATTR_NO_20MHZ not in attrs:
        widths.append(20)
    ht40_blocked = (
        nl.FREQ_ATTR_NO_HT40_MINUS in attrs and nl.FREQ_ATTR_NO_HT40_PLUS in attrs
    )
    if ht and not ht40_blocked:
        widths.append(40)
    if wide and nl.FREQ_ATTR_NO_80MHZ not in attrs:
        widths.append(80)
    if wide and nl.FREQ_ATTR_NO_160MHZ not in attrs:
        widths.append(160)
    if eht and nl.FREQ_ATTR_NO_320MHZ not in attrs:
        widths.append(320)
    return widths


def _phy_flags(attrs: dict[int, bytes]) -> set[str]:
    flags = set()
    if nl.BAND_ATTR_HT_MCS_SET in attrs or nl.BAND_ATTR_HT_CAPA in attrs:
        flags.add("HT")
    if nl.BAND_ATTR_VHT_MCS_SET in attrs or nl.BAND_ATTR_VHT_CAPA in attrs:
        flags.add("VHT")
    blob = attrs.get(nl.BAND_ATTR_IFTYPE_DATA)
    if not blob:
        return flags
    for _index, payload in nl.parse_attrs(blob).items():
        inner = nl.parse_attrs(payload)
        if nl.BAND_IFTYPE_HE_CAP_PHY in inner:
            flags.add("HE")
        if nl.BAND_IFTYPE_EHT_CAP_MAC in inner:
            flags.add("EHT")
    return flags


def _concat_nested(chunks: list[bytes]) -> bytes:
    entries: list[bytes] = []
    for blob in chunks:
        entries.extend(
            payload for _index, payload in nl.parse_attrs(blob).items() if payload
        )
    return b"".join(
        nl.pack_attr((index + 1) | nl.NLA_F_NESTED, payload)
        for index, payload in enumerate(entries)
    )


def _merge_band_payloads(chunks: list[bytes]) -> bytes:
    if len(chunks) == 1:
        return chunks[0]
    merged: dict[int, bytes] = {}
    freq_chunks: list[bytes] = []
    iftype_chunks: list[bytes] = []
    for chunk in chunks:
        for kind, payload in nl.parse_attrs(chunk).items():
            if kind == nl.BAND_ATTR_FREQS:
                freq_chunks.append(payload)
            elif kind == nl.BAND_ATTR_IFTYPE_DATA:
                iftype_chunks.append(payload)
            elif kind not in merged or not merged[kind]:
                merged[kind] = payload
    parts = [nl.pack_attr(kind, payload) for kind, payload in merged.items()]
    if freq_chunks:
        parts.append(
            nl.pack_attr(
                nl.BAND_ATTR_FREQS | nl.NLA_F_NESTED, _concat_nested(freq_chunks)
            )
        )
    if iftype_chunks:
        parts.append(
            nl.pack_attr(
                nl.BAND_ATTR_IFTYPE_DATA | nl.NLA_F_NESTED,
                _concat_nested(iftype_chunks),
            )
        )
    return b"".join(parts)


def summarize_bands(bands: dict[int, bytes]) -> tuple[list[dict], list[str]]:
    """Supported channel runs and PHY generations from NL80211_ATTR_WIPHY_BANDS."""
    parsed: list[dict[str, Any]] = []
    phy: set[str] = set()
    for band_id, payload in bands.items():
        attrs = nl.parse_attrs(payload)
        flags = _phy_flags(attrs)
        phy |= flags
        ht = "HT" in flags
        wide = bool(flags & {"VHT", "HE", "EHT"})
        eht = "EHT" in flags
        channels: list[dict[str, Any]] = []
        for _index, raw in nl.parse_attrs(attrs.get(nl.BAND_ATTR_FREQS, b"")).items():
            freq = nl.parse_attrs(raw)
            if nl.FREQ_ATTR_DISABLED in freq:
                continue
            mhz = nl.get_uint(freq, nl.FREQ_ATTR_FREQ)
            number = channel_number(mhz)
            if number is None:
                continue
            channels.append(
                {
                    "number": number,
                    "widths": _freq_widths(freq, ht, wide, eht),
                    "radar": nl.FREQ_ATTR_RADAR in freq,
                    "no_ir": nl.FREQ_ATTR_NO_IR in freq,
                }
            )
        if not channels:
            continue
        numbers = [int(item["number"]) for item in channels]
        radar = [int(item["number"]) for item in channels if item["radar"]]
        no_ir = [int(item["number"]) for item in channels if item["no_ir"]]
        widths = sorted({int(width) for item in channels for width in item["widths"]})
        parsed.append(
            {
                "id": band_id,
                "band": _BAND_LABELS.get(band_id, str(band_id)),
                "ranges": _channel_runs(numbers, band_id),
                "widths_mhz": widths,
                "dfs": _channel_runs(radar, band_id) if radar else None,
                "dfs_all": set(radar) == set(numbers) if radar else False,
                "no_ir": _channel_runs(no_ir, band_id) if no_ir else None,
                "no_ir_all": set(no_ir) == set(numbers) if no_ir else False,
            }
        )
    order = [band for band in _BAND_ORDER if any(item["id"] == band for item in parsed)]
    order.extend(sorted(item["id"] for item in parsed if item["id"] not in order))
    by_id = {item["id"]: item for item in parsed}
    summary = [by_id[band] for band in order]
    generations = [name for name in _PHY_ORDER if name in phy]
    return summary, generations


def format_supported_channels(summary: list[dict]) -> str:
    parts = []
    for band in summary:
        ranges = [
            str(start) if start == end else f"{start}-{end}"
            for start, end in band["ranges"]
        ]
        text = f"{band['band']} {', '.join(ranges)}"
        notes = []
        if band.get("dfs"):
            notes.append(
                "DFS" if band.get("dfs_all") else f"DFS {_range_text(band['dfs'])}"
            )
        if band.get("no_ir"):
            notes.append(
                "no-IR"
                if band.get("no_ir_all")
                else f"no-IR {_range_text(band['no_ir'])}"
            )
        chunks = []
        if band["widths_mhz"]:
            chunks.append("/".join(str(width) for width in band["widths_mhz"]))
        chunks.extend(notes)
        if chunks:
            text += f" ({'; '.join(chunks)})"
        parts.append(text)
    return ", ".join(parts)


def public_supported_channels(summary: list[dict]) -> list[dict]:
    public = []
    for band in summary:
        item: dict[str, Any] = {
            "band": band["band"],
            "ranges": band["ranges"],
            "widths_mhz": band["widths_mhz"],
        }
        if band.get("dfs"):
            item["dfs"] = band["dfs"]
        if band.get("no_ir"):
            item["no_ir"] = band["no_ir"]
        public.append(item)
    return public


def survey_busy_percent(messages, frequency_mhz: int | None) -> float | None:
    """TIME_BUSY / TIME for the in-use survey, else the operating frequency."""
    fallback = None
    for message in messages:
        info = nl.parse_attrs(message.attrs.get(nl.ATTR_SURVEY_INFO, b""))
        total = _uint(info, nl.SURVEY_TIME)
        busy = _uint(info, nl.SURVEY_TIME_BUSY)
        if total is None or busy is None or total == 0:
            continue
        percent = round(100 * busy / total, 1)
        if nl.SURVEY_IN_USE in info:
            return percent
        freq = nl.get_uint(info, nl.SURVEY_FREQUENCY)
        if frequency_mhz is not None and freq == frequency_mhz:
            fallback = percent
    return fallback


def country_text(code: str | None) -> str | None:
    if code == "00":
        return "00 (world)"
    return code


def default_gateway(proc_net: str, device: str) -> tuple[str | None, str | None]:
    """Default gateway for device from /proc/net/route and /proc/net/arp."""
    try:
        with open(os.path.join(proc_net, "route"), encoding="utf-8") as handle:
            routes = handle.readlines()
    except OSError:
        return None, None
    gateway_ip = None
    for line in routes[1:]:
        parts = line.split()
        if len(parts) < 3 or parts[0] != device or parts[1].lower() != "00000000":
            continue
        try:
            raw = bytes.fromhex(parts[2])
        except ValueError:
            return None, None
        if len(raw) != 4 or raw == b"\x00\x00\x00\x00":
            return None, None
        gateway_ip = ".".join(str(octet) for octet in reversed(raw))
        break
    if gateway_ip is None:
        return None, None
    try:
        with open(os.path.join(proc_net, "arp"), encoding="utf-8") as handle:
            arp_lines = handle.readlines()
    except OSError:
        return gateway_ip, None
    mac = None
    for line in arp_lines[1:]:
        parts = line.split()
        if len(parts) < 6 or parts[0] != gateway_ip or parts[5] != device:
            continue
        try:
            flags = int(parts[2], 16)
        except ValueError:
            continue
        if flags & 0x2 and parts[3] != "00:00:00:00:00:00":
            mac = parts[3].lower()
            break
    return gateway_ip, mac


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
            return bool(int(flags, 16) & IFF_UP)
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
        proc_net: str = "/proc/net",
    ) -> None:
        self._netlink = netlink or nl.GenericNetlink
        self.sysfs = sysfs or Sysfs()
        self.scan_timeout = scan_timeout
        self.proc_net = proc_net
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

    def _bss_messages(self, native: LinuxInterface):
        try:
            with self.netlink() as sock:
                return sock.request(
                    nl.CMD_GET_SCAN,
                    nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex),
                    dump=True,
                )
        except OSError as error:
            log.debug("GET_SCAN on %s failed: %s", native.name, error)
            return []

    def link(self, native: LinuxInterface) -> LinkInfo:
        """Current SSID, BSSID, channel, RSSI and Tx rate"""
        native = self.refresh(native)
        iface_links = [dict(item) for item in native.links]
        freq, width, center1, center2, tx_power = _fill_from_link(
            iface_links,
            native.frequency_mhz,
            native.width_mhz,
            native.center_freq1,
            native.center_freq2,
            native.tx_power_mbm,
        )
        radio = {"iftype": native.iftype, "tx_power_mbm": tx_power}
        if self.sysfs.is_up(native.name) is False:
            # some drivers (brcmfmac) keep reporting the last channel while down
            return LinkInfo(connected=False, extra=radio)
        info = LinkInfo(
            connected=bool(native.ssid),
            ssid=native.ssid,
            frequency_mhz=freq,
            width_mhz=width,
            extra=radio | {"center_freq1": center1, "center_freq2": center2},
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
        bssid, station, station_links = merge_station_dump(stations)
        mld, bss_links = associated_mlo_links(self._bss_messages(native))
        if bssid is None:
            bssid = mld
        local = _local_addrs(iface_links)
        station_links = [_unlocal_bssid(item, local) for item in station_links]
        links = _merge_links(iface_links + station_links + bss_links)
        freq, width, center1, center2, tx_power = _fill_from_link(
            links, freq, width, center1, center2, tx_power
        )
        info.frequency_mhz = freq
        info.width_mhz = width
        info.extra["center_freq1"] = center1
        info.extra["center_freq2"] = center2
        info.extra["tx_power_mbm"] = tx_power
        _drop_placeholder_mld_signal(station, links)
        info.bssid = bssid
        if station:
            tx = station.get("tx_rate") or {}
            info.rssi = station.get("signal")
            info.tx_rate_mbps = tx.get("mbps")
            info.extra["station"] = station
        public = []
        for item in links:
            shown = _public_link(item)
            if shown:
                public.append(shown)
        if public:
            info.extra["links"] = public
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

    def channel_busy_percent(self, native: LinuxInterface, frequency_mhz: int | None):
        try:
            with self.netlink() as sock:
                replies = sock.request(
                    nl.CMD_GET_SURVEY,
                    nl.attr_u32(nl.ATTR_IFINDEX, native.ifindex),
                    dump=True,
                )
        except OSError as error:
            log.debug("GET_SURVEY on %s failed: %s", native.name, error)
            return None
        return survey_busy_percent(replies, frequency_mhz)

    def radio(self, native: LinuxInterface) -> tuple[list | None, list | None]:
        """Supported channels and PHY generations. None when the wiphy omits them."""
        if native.wiphy is None:
            return None, None
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
            return None, None
        parts: dict[int, list[bytes]] = {}
        for reply in replies:
            seen = nl.get_uint(reply.attrs, nl.ATTR_WIPHY)
            if seen is not None and seen != native.wiphy:
                continue
            blob = reply.attrs.get(nl.ATTR_WIPHY_BANDS)
            if not blob:
                continue
            for band_id, payload in nl.parse_attrs(blob).items():
                parts.setdefault(band_id, []).append(payload)
        bands = {
            band_id: _merge_band_payloads(chunks) for band_id, chunks in parts.items()
        }
        summary, phy = summarize_bands(bands)
        return (summary or None), (phy or None)

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
                [nl.pack_attr(1, WILDCARD_SSID)],
            )
            colocated = self.supports_6ghz(native)
            if native.ssid:
                log.info(
                    "%s is associated; the scan may briefly pause its traffic",
                    native.name,
                )
            drop_queued_events(events)
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

    def interface_info(self, args, iface: InterfaceInfo) -> str:
        """-ap, -channel, --get-interfaces from nl80211 and sysfs"""
        native = self._native(iface)
        if args.supported:
            return (
                f"    --supported: {UNSUPPORTED}\n"
                "    AP uptime isn't available on Linux\n"
            )
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
        bus_text = f"{bus_type} {bus}" if bus_type else None
        mbm = link.extra.get("tx_power_mbm")
        tx_power = mbm / 100 if mbm is not None else None
        iftype = link.extra.get("iftype")
        station = link.extra.get("station") or {}
        links = link.extra.get("links") or None
        tx_rate = station.get("tx_rate")
        rx_rate = station.get("rx_rate")
        channels, phy = self.radio(native)
        busy = (
            self.channel_busy_percent(native, link.frequency_mhz)
            if link.frequency_mhz is not None
            else None
        )
        gateway_ip, gateway_mac = (None, None)
        if link.connected:
            gateway_ip, gateway_mac = default_gateway(self.proc_net, native.name)
        code = self.country_code()

        def rate_json(rate: dict | None) -> dict | None:
            if not rate:
                return None
            return {
                "mbps": rate["mbps"],
                "phy": rate.get("phy"),
                "mcs": rate.get("mcs"),
                "nss": rate.get("nss"),
                "width_mhz": rate.get("width_mhz"),
                "gi": rate.get("gi"),
            }

        info = base | {
            "description": iface.description,
            "state": state,
            "ssid": link.ssid_text,
            "bssid": link.bssid,
            "channel": link.channel,
            "frequency_mhz": link.frequency_mhz,
            "band": link.band,
            "width_mhz": link.width_mhz,
            "center_freq1_mhz": link.extra.get("center_freq1"),
            "center_freq2_mhz": link.extra.get("center_freq2"),
            "interface_mode": nl.IFTYPE_NAMES.get(iftype)
            if iftype is not None
            else None,
            "rssi": link.rssi,
            "signal_chains": station.get("signal_chains"),
            "signal_avg": station.get("signal_avg"),
            "signal_avg_chains": station.get("signal_avg_chains"),
            "beacon_signal_avg": station.get("beacon_signal_avg"),
            "ack_signal": station.get("ack_signal"),
            "ack_signal_avg": station.get("ack_signal_avg"),
            "tx_rate_mbps": link.tx_rate_mbps,
            "tx_rate": rate_json(tx_rate),
            "rx_rate_mbps": rx_rate["mbps"] if rx_rate else None,
            "rx_rate": rate_json(rx_rate),
            "tx_retries": station.get("tx_retries"),
            "tx_failed": station.get("tx_failed"),
            "rx_packets": station.get("rx_packets"),
            "tx_packets": station.get("tx_packets"),
            "rx_bytes": station.get("rx_bytes"),
            "tx_bytes": station.get("tx_bytes"),
            "tx_duration_us": station.get("tx_duration_us"),
            "rx_duration_us": station.get("rx_duration_us"),
            "connected_time_s": station.get("connected_time_s"),
            "inactive_time_ms": station.get("inactive_time_ms"),
            "beacon_loss": station.get("beacon_loss"),
            "expected_throughput_mbps": station.get("expected_throughput_mbps"),
            "channel_busy_percent": busy,
            "tx_power_dbm": tx_power,
            "supported_channels": public_supported_channels(channels)
            if channels
            else None,
            "phy": phy,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "links": links,
            "country_code": code,
            "bus": bus_text,
        }
        if args.json:
            return json.dumps(info, indent=args.json_indent, default=str)
        lines = [
            f"Interface: {iface.connection_name} is {state}",
            f"    Description: {iface.description}",
            f"    MAC: {iface.mac}",
        ]
        if bus_text:
            lines.append(f"    Bus: {bus_text}")
        lines.append(f"    State: {state}")
        if info["interface_mode"]:
            lines.append(f"    Mode: {info['interface_mode']}")
        if link.connected:
            lines.append(f"    SSID: {link.ssid_text}")
            label = "AP MLD" if links else "BSSID"
            lines.append(f"    {label}: {link.bssid}")
            for item in links or []:
                lines.append(f"    {format_link(item)}")
        if link.frequency_mhz is not None:
            if link.channel is not None:
                lines.append(f"    Channel: {link.channel}")
            lines.append(f"    Frequency: {link.frequency_mhz} MHz")
            if link.band is not None:
                lines.append(f"    Band: {link.band}")
            if link.width_mhz is not None:
                lines.append(f"    Width: {link.width_mhz} MHz")
            if info["center_freq1_mhz"] is not None:
                lines.append(f"    Center Frequency: {info['center_freq1_mhz']} MHz")
            if info["center_freq2_mhz"] is not None:
                lines.append(f"    Center Frequency 2: {info['center_freq2_mhz']} MHz")
        if link.connected:

            def dbm(label: str, key: str, chain_key: str | None = None) -> None:
                if key not in station:
                    return
                text = f"{station[key]} dBm"
                chains = station.get(chain_key) if chain_key else None
                if chains:
                    text += f" (chains {', '.join(str(item) for item in chains)})"
                lines.append(f"    {label}: {text}")

            def stat(label: str, key: str, suffix: str = "") -> None:
                if key not in station:
                    return
                lines.append(f"    {label}: {station[key]}{suffix}")

            dbm("RSSI", "signal", "signal_chains")
            dbm("Signal Avg", "signal_avg", "signal_avg_chains")
            dbm("Beacon Signal Avg", "beacon_signal_avg")
            dbm("Ack Signal", "ack_signal")
            dbm("Ack Signal Avg", "ack_signal_avg")
            if tx_rate:
                lines.append(f"    Transmit (Tx) Rate: {format_rate(tx_rate)}")
            elif link.tx_rate_mbps is not None:
                lines.append(
                    f"    Transmit (Tx) Rate: {format_mbps(link.tx_rate_mbps)} Mbps"
                )
            if rx_rate:
                lines.append(f"    Receive (Rx) Rate: {format_rate(rx_rate)}")
            stat("Tx Retries", "tx_retries")
            stat("Tx Failed", "tx_failed")
            stat("Rx Packets", "rx_packets")
            stat("Tx Packets", "tx_packets")
            stat("Rx Bytes", "rx_bytes")
            stat("Tx Bytes", "tx_bytes")
            stat("Connected Time", "connected_time_s", " s")
            stat("Inactive Time", "inactive_time_ms", " ms")
            stat("Beacon Loss", "beacon_loss")
            stat("Tx Duration", "tx_duration_us", " us")
            stat("Rx Duration", "rx_duration_us", " us")
            if station.get("expected_throughput_mbps") is not None:
                lines.append(
                    "    Expected Throughput: "
                    f"{format_mbps(station['expected_throughput_mbps'])} Mbps"
                )
            if gateway_ip:
                lines.append(f"    Gateway: {gateway_ip}")
            if gateway_mac:
                lines.append(f"    Gateway MAC: {gateway_mac}")
        if busy is not None:
            lines.append(f"    Channel Busy: {format_mbps(busy)}%")
        if tx_power is not None:
            lines.append(f"    Transmit Power: {format_mbps(tx_power)} dBm")
        if channels:
            lines.append(
                f"    Supported Channels: {format_supported_channels(channels)}"
            )
        if phy:
            lines.append(f"    PHY: {', '.join(phy)}")
        if code:
            lines.append(f"    Country Code: {country_text(code)}")
        return "\n".join(lines) + "\n"
