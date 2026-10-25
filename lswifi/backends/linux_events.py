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
lswifi.backends.linux_events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

--watchevents on Linux: the nl80211 "mlme" and "scan" multicast groups.

The kernel pushes connect, roam, disconnect (with the 802.11 reason code
and whether the AP or this station ended it), port authorized (4-way
handshake done) and channel switch events, so nothing is polled. A link
added or removed, and a channel switch that names a link, are reported for
that link. Lines use the same layout and --json schema as the Windows and
macOS watchers. scan_cache_updated lines print only with --debug, as on
macOS.
"""

import logging
from collections.abc import Callable
from typing import Any

from lswifi.backends import nl80211 as nl
from lswifi.backends.base import BackendError, InterfaceInfo
from lswifi.backends.linux import (
    LinkInfo,
    LinuxInterface,
    _public_link,
    band_name,
    channel_number,
    parse_mlo_links,
)
from lswifi.backends.macos_events import EventLine, reason_text
from lswifi.helpers import format_mbps
from lswifi.watchjson import event_record, shared_writer, watch_json_requested

log = logging.getLogger(__name__)

# IEEE 802.11-2020 Table 9-50, the common status codes for connect_failed
STATUS_CODES = {
    1: "unspecified failure",
    10: "cannot support all requested capabilities",
    12: "denied for another reason",
    13: "unsupported authentication algorithm",
    15: "challenge failure",
    16: "authentication timeout",
    17: "AP unable to handle more STAs",
    18: "basic rates not supported",
    30: "try again later (association comeback)",
    37: "request declined",
    53: "invalid PMKID",
    72: "invalid RSNE",
    77: "group cipher not supported",
    82: "rejected with suggested BSS transition",
}


def status_text(code: int) -> str:
    return STATUS_CODES.get(code, "see IEEE 802.11 Table 9-50")


def _snapshot(link: LinkInfo) -> dict[str, Any]:
    links = list(link.extra.get("links") or [])
    freq = link.frequency_mhz
    width = link.width_mhz
    channel = link.channel
    band = link.band
    if len(links) > 1 and freq is None:
        primary = next((item for item in links if item.get("id") == 0), links[0])
        freq = primary.get("frequency_mhz")
        width = primary.get("width_mhz")
        channel = primary.get("channel")
        if channel is None:
            channel = channel_number(freq)
        band = primary.get("band") or band_name(freq)
    rssi = link.rssi
    if rssi == 0 and links:
        rssi = None
    return {
        "freq": freq,
        "width": width,
        "channel": channel,
        "band": band,
        "rssi": rssi,
        "links": links,
    }


def _channel_text(snap: dict[str, Any]) -> str:
    if snap.get("channel") is None:
        return ""
    text = str(snap["channel"])
    if snap.get("width"):
        text += f"@{snap['width']}"
    if snap.get("band"):
        text += f" {snap['band']}"
    return text


def _channel_fields(snap: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    return {
        f"{prefix}channel": snap.get("channel"),
        f"{prefix}width_mhz": snap.get("width"),
        f"{prefix}band": snap.get("band"),
    }


def describe_link(item: dict[str, Any]) -> str:
    ident = item.get("id")
    mac = item.get("bssid") or item.get("addr") or ""
    freq = item.get("frequency_mhz")
    channel = item.get("channel")
    if channel is None and freq:
        channel = channel_number(freq)
    band = item.get("band") or (band_name(freq) if freq else None)
    width = item.get("width_mhz")
    body: list[str] = []
    if mac:
        body.append(str(mac))
    if band:
        body.append(str(band))
    if channel is not None:
        ch = f"ch {channel}"
        if width:
            ch += f"@{width}"
        body.append(ch)
    text = " ".join(body)
    if ident is None:
        return text
    if not text:
        return str(ident)
    return f"{ident}: {text}"


def describe_links(items: list[dict[str, Any]]) -> str:
    return ", ".join(text for item in items if (text := describe_link(item)))


def links_from_attrs(attrs: dict[int, bytes]) -> list[dict[str, Any]]:
    found = []
    for item in parse_mlo_links(attrs):
        shown = _public_link(item)
        if shown:
            found.append(shown)
    return found


def _association_id(links: list[dict[str, Any]]) -> Any:
    for item in links:
        if item.get("id") == 0:
            return 0
    if links:
        return links[0].get("id")
    return None


def _overlay_link(
    links: list[dict[str, Any]], link_id: int, freq: int | None, width: int | None
) -> list[dict[str, Any]]:
    updated: list[dict[str, Any]] = []
    found = False
    for item in links:
        current = dict(item)
        if current.get("id") == link_id:
            found = True
            _apply_chandef(current, freq, width)
        updated.append(current)
    if not found:
        created: dict[str, Any] = {"id": link_id}
        _apply_chandef(created, freq, width)
        updated.append(created)
    return updated


def _prefer(known: list[dict[str, Any]], items: list[dict[str, Any]]) -> list[dict]:
    by_id = {item.get("id"): item for item in known if item.get("id") is not None}
    chosen = []
    for item in items:
        base = dict(by_id.get(item.get("id")) or {})
        for key, value in item.items():
            if key not in base or base[key] in (None, ""):
                base[key] = value
        shown = _public_link(base)
        chosen.append(shown or base)
    return chosen


def _apply_chandef(item: dict[str, Any], freq: int | None, width: int | None) -> None:
    if freq is not None:
        item["frequency_mhz"] = freq
        number = channel_number(freq)
        if number is not None:
            item["channel"] = number
        band = band_name(freq)
        if band:
            item["band"] = band
    if width is not None:
        item["width_mhz"] = width


class LinkFormatter:
    """--watchevents lines for one interface, remembering the last link"""

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.last: LinkInfo = LinkInfo()

    def line(
        self, link: LinkInfo, event: str, extra: str = "", **fields: Any
    ) -> EventLine:
        affected = fields.pop("affected", None)
        snap = _snapshot(link)
        mlo_text, mlo_fields = self._mlo(link, snap)
        record = event_record(
            self.mac,
            event,
            bssid=link.bssid,
            freq=snap["freq"] if link.connected else None,
            ssid=link.ssid if link.connected else None,
            rssi=snap["rssi"] if link.connected else None,
            **fields,
            **mlo_fields,
        )
        if affected is not None:
            record["link"] = affected
        if link.connected:
            record["freq_mhz"] = snap["freq"]
            record["rssi"] = snap["rssi"]
            record["channel"] = snap["channel"]
            record["width_mhz"] = snap["width"]
            record["band"] = snap["band"]
        parts = [f"({self.mac})"]
        if link.bssid:
            if link.connected and snap["links"]:
                parts.append(f"ap_mld: ({link.bssid})")
            else:
                parts.append(f"bssid: ({link.bssid})")
        if link.connected:
            if snap["freq"] is not None:
                parts.append(f"freq: ({snap['freq']})")
            if link.ssid:
                parts.append(f"ssid: ({link.ssid_text})")
            if snap["rssi"] is not None:
                parts.append(f"rssi: ({snap['rssi']})")
        parts.append(f"event: ({event})")
        return EventLine(", ".join(parts) + extra + mlo_text, record)

    def _mlo(self, link: LinkInfo, snap: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        links = snap["links"]
        if not link.connected or not links:
            return "", {}
        fields: dict[str, Any] = {"links": [dict(item) for item in links]}
        extra = ""
        if link.bssid:
            fields["mld"] = link.bssid
        rendered = describe_links(links)
        if rendered:
            extra += f", links: ({rendered})"
        return extra, fields

    def link_extra(self, link: LinkInfo) -> tuple[str, dict]:
        if not link.connected:
            return "", {}
        snap = _snapshot(link)
        extra = ""
        fields: dict[str, Any] = {}
        text = _channel_text(snap)
        if text:
            extra = f", channel: ({text})"
            fields.update(_channel_fields(snap))
        if link.tx_rate_mbps is not None:
            extra += f", tx_rate: ({format_mbps(link.tx_rate_mbps)} Mbps)"
            fields["tx_rate_mbps"] = link.tx_rate_mbps
        return extra, fields

    def watching(self, link: LinkInfo) -> EventLine:
        self.last = link
        extra, fields = self.link_extra(link)
        return self.line(link, "watching", extra, **fields)

    def connected(self, link: LinkInfo) -> EventLine:
        old, self.last = self.last, link
        extra, fields = self.link_extra(link)
        if old.bssid and link.bssid and old.bssid != link.bssid:
            # reconnect to a different AP after the link went down; not a roam
            extra += f", old_bssid: ({old.bssid})"
            fields["old_bssid"] = old.bssid
        return self.line(link, "connected", extra, **fields)

    def connect_failed(self, bssid: str, status: int, timed_out: bool) -> EventLine:
        self.last = LinkInfo(bssid=self.last.bssid)
        target = LinkInfo(bssid=bssid or None)
        extra = f", status: ({status} {status_text(status)})"
        fields: dict[str, Any] = {
            "status_code": status,
            "status_text": status_text(status),
        }
        if timed_out:
            extra += ", timed_out: (yes)"
            fields["timed_out"] = True
        return self.line(target, "connect_failed", extra, **fields)

    def roamed(self, link: LinkInfo) -> EventLine:
        old, self.last = self.last, link
        extra, fields = self.link_extra(link)
        if old.bssid:
            extra += f", old_bssid: ({old.bssid})"
            fields["old_bssid"] = old.bssid
        old_snap, new_snap = _snapshot(old), _snapshot(link)
        if old_snap["freq"] != new_snap["freq"] and old_snap["freq"] is not None:
            extra += f", old_freq: ({old_snap['freq']})"
            fields["old_freq_mhz"] = old_snap["freq"]
        if old_snap["rssi"] is not None:
            extra += f", old_rssi: ({old_snap['rssi']})"
            fields["old_rssi"] = old_snap["rssi"]
        old_channel = _channel_text(old_snap)
        if old_channel and old_channel != _channel_text(new_snap):
            extra += f", old_channel: ({old_channel})"
            fields.update(_channel_fields(old_snap, "old_"))
        return self.line(link, "roamed", extra, **fields)

    def disconnected(self, reason: int | None, by_ap: bool) -> EventLine:
        old = self.last
        self.last = LinkInfo(bssid=old.bssid)
        gone = LinkInfo(bssid=old.bssid)
        extra = ""
        fields: dict[str, Any] = {}
        if reason is not None:
            extra += f", reason: ({reason} {reason_text(reason)})"
            fields.update(reason_code=reason, reason_text=reason_text(reason))
        extra += f", locally_generated: ({'no' if by_ap else 'yes'})"
        fields["locally_generated"] = not by_ap
        return self.line(gone, "disconnected", extra, **fields)

    def port_authorized(self, link: LinkInfo) -> EventLine:
        self.last = link
        return self.line(link, "port_authorized")

    def channel_change(self, link: LinkInfo) -> EventLine | None:
        old, self.last = self.last, link
        old_text = _channel_text(_snapshot(old))
        new_text = _channel_text(_snapshot(link))
        if old_text == new_text:
            return None
        extra = ""
        fields: dict[str, Any] = {}
        if new_text:
            extra += f", channel: ({new_text})"
            fields.update(_channel_fields(_snapshot(link)))
        if old_text:
            extra += f", old_channel: ({old_text})"
            fields.update(_channel_fields(_snapshot(old), "old_"))
        return self.line(link, "channel_change", extra, **fields)

    def link_channel(
        self,
        link: LinkInfo,
        link_id: int,
        freq: int | None,
        width: int | None,
        *,
        started: bool,
    ) -> EventLine:
        previous = list(self.last.extra.get("links") or [])
        old_item = next((item for item in previous if item.get("id") == link_id), None)
        current = list(link.extra.get("links") or previous)
        updated = _overlay_link(current, link_id, freq, width)
        new_item = next(item for item in updated if item.get("id") == link_id)
        if not started:
            link.extra["links"] = updated
            if _association_id(updated) == link_id:
                if freq is not None:
                    link.frequency_mhz = freq
                if width is not None:
                    link.width_mhz = width
        self.last = link
        event = "link_channel_switch_started" if started else "link_channel_change"
        extra = f", link: ({describe_link(new_item)})"
        fields: dict[str, Any] = {
            "affected": [_public_link(new_item) or {"id": link_id}]
        }
        if old_item and describe_link(old_item) != describe_link(new_item):
            extra += f", old_link: ({describe_link(old_item)})"
            fields["old_link"] = [_public_link(old_item) or {"id": link_id}]
        return self.line(link, event, extra, **fields)

    def link_added(self, link: LinkInfo, added: list[dict[str, Any]]) -> EventLine:
        current = list(link.extra.get("links") or [])
        known = {item.get("id") for item in current}
        for item in added:
            if item.get("id") not in known:
                current.append(item)
        link.extra["links"] = current
        self.last = link
        described = _prefer(current, added)
        return self.line(
            link,
            "link_added",
            f", link: ({describe_links(described)})",
            affected=described,
        )

    def link_removed(self, link: LinkInfo, removed: list[dict[str, Any]]) -> EventLine:
        previous = list(self.last.extra.get("links") or [])
        described = _prefer(previous, removed)
        self.last = link
        return self.line(
            link,
            "link_removed",
            f", link: ({describe_links(described)})",
            affected=described,
        )

    def scan_cache(self, count: int) -> EventLine:
        return self.line(
            self.last,
            "scan_cache_updated",
            f", scan: ({count} BSSIDs found)",
            scan_bssid_count=count,
        )


class LinuxEventWatcher:
    """Prints --watchevents lines for every station interface"""

    def __init__(
        self,
        backend: Any,
        interfaces: list[InterfaceInfo],
        args: Any,
        emit: Callable[[EventLine], None] | None = None,
    ) -> None:
        self.backend = backend
        self.args = args
        self.interfaces: dict[int, LinuxInterface] = {}
        self.formatters: dict[int, LinkFormatter] = {}
        for info in interfaces:
            self.add(info)
        self.emit = emit or self._emit
        self.json_writer = shared_writer() if watch_json_requested(args) else None
        self.scan_events = getattr(args, "debug", logging.INFO) == logging.DEBUG

    def add(self, info: InterfaceInfo) -> None:
        native = info.native
        if isinstance(native, LinuxInterface):
            self.interfaces[native.ifindex] = native
            self.formatters[native.ifindex] = LinkFormatter(info.mac)

    def _emit(self, line: str) -> None:
        record = getattr(line, "record", None)
        if self.json_writer is not None and record is not None:
            self.json_writer.write(record)
        else:
            log.info(line)
        if getattr(self.args, "syslog", None):
            from lswifi.slog import message as syslog

            syslog(line, "INFO")

    def _link(self, native: LinuxInterface) -> LinkInfo:
        try:
            return self.backend.link(native)
        except OSError as error:
            log.debug("reading link state of %s failed: %s", native.name, error)
            return LinkInfo()

    def start(self) -> list[EventLine]:
        return [
            self.formatters[ifindex].watching(self._link(native))
            for ifindex, native in self.interfaces.items()
        ]

    def handle(self, message: nl.GenlMessage) -> list[EventLine]:
        """Lines for one nl80211 multicast message"""
        ifindex = nl.get_uint(message.attrs, nl.ATTR_IFINDEX)
        if ifindex is None:
            return []
        if ifindex not in self.interfaces:
            for info in self.backend.list_interfaces():
                if info.native.ifindex == ifindex:
                    self.add(info)
                    break
            else:
                return []
        native, formatter = self.interfaces[ifindex], self.formatters[ifindex]
        cmd = message.cmd
        if cmd == nl.CMD_CONNECT:
            status = nl.get_uint(message.attrs, nl.ATTR_STATUS_CODE, 0) or 0
            if status:
                return [
                    formatter.connect_failed(
                        nl.mac_str(message.attrs.get(nl.ATTR_MAC)),
                        status,
                        nl.ATTR_TIMED_OUT in message.attrs,
                    )
                ]
            return [formatter.connected(self._link(native))]
        if cmd == nl.CMD_ROAM:
            return [formatter.roamed(self._link(native))]
        if cmd == nl.CMD_DISCONNECT:
            return [
                formatter.disconnected(
                    nl.get_uint(message.attrs, nl.ATTR_REASON_CODE),
                    nl.ATTR_DISCONNECTED_BY_AP in message.attrs,
                )
            ]
        if cmd == nl.CMD_PORT_AUTHORIZED:
            return [formatter.port_authorized(self._link(native))]
        if cmd in (nl.CMD_CH_SWITCH_NOTIFY, nl.CMD_CH_SWITCH_STARTED_NOTIFY):
            freq = nl.get_uint(message.attrs, nl.ATTR_WIPHY_FREQ)
            width_code = nl.get_uint(message.attrs, nl.ATTR_CHANNEL_WIDTH)
            width = (
                nl.CHAN_WIDTH_MHZ.get(width_code) if width_code is not None else None
            )
            started = cmd == nl.CMD_CH_SWITCH_STARTED_NOTIFY
            link_id = nl.get_uint(message.attrs, nl.ATTR_MLO_LINK_ID)
            if link_id is not None:
                return [
                    formatter.link_channel(
                        self._link(native), link_id, freq, width, started=started
                    )
                ]
            if started:
                return []
            link = self._link(native)
            if freq:
                link.frequency_mhz = freq
            if width is not None:
                link.width_mhz = width
            changed = formatter.channel_change(link)
            return [changed] if changed else []
        if cmd == nl.CMD_LINKS_REMOVED:
            removed = links_from_attrs(message.attrs)
            if not removed:
                return []
            return [formatter.link_removed(self._link(native), removed)]
        if cmd == nl.CMD_ASSOC_MLO_RECONF:
            if nl.get_uint(message.attrs, nl.ATTR_STATUS_CODE, 0):
                return []
            added = links_from_attrs(message.attrs)
            if not added:
                return []
            return [formatter.link_added(self._link(native), added)]
        if cmd == nl.CMD_NEW_SCAN_RESULTS and self.scan_events:
            try:
                count = len(self.backend.dump_scan(native))
            except (OSError, BackendError) as error:
                log.debug("%s: scan dump failed: %s", native.name, error)
                return []
            return [formatter.scan_cache(count)]
        return []

    def run(self) -> None:
        with self.backend.netlink() as events:
            events.join(nl.MCAST_GROUP_MLME, nl.MCAST_GROUP_SCAN)
            for line in self.start():
                self.emit(line)
            while True:
                for message in events.events(1.0):
                    for line in self.handle(message):
                        self.emit(line)


__all__ = ["LinkFormatter", "LinuxEventWatcher", "status_text"]
