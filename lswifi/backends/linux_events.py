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
handshake done) and channel switch events, so nothing is polled. Lines use
the same layout and --json schema as the Windows and macOS watchers.
scan_cache_updated lines print only with --debug, as on macOS.
"""

import logging
from collections.abc import Callable
from typing import Any

from lswifi.backends import nl80211 as nl
from lswifi.backends.base import BackendError, InterfaceInfo
from lswifi.backends.linux import LinkInfo, LinuxInterface
from lswifi.backends.macos_events import EventLine, reason_text
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


def _channel_json(link: LinkInfo, prefix: str = "") -> dict:
    return {
        f"{prefix}channel": link.channel,
        f"{prefix}width_mhz": link.width_mhz,
        f"{prefix}band": link.band,
    }


def _channel(link: LinkInfo) -> str:
    if link.channel is None:
        return ""
    text = str(link.channel)
    if link.width_mhz:
        text += f"@{link.width_mhz}"
    if link.band:
        text += f" {link.band}"
    return text


class LinkFormatter:
    """--watchevents lines for one interface, remembering the last link"""

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.last: LinkInfo = LinkInfo()

    def line(
        self, link: LinkInfo, event: str, extra: str = "", **fields: Any
    ) -> EventLine:
        record = event_record(
            self.mac,
            event,
            bssid=link.bssid,
            freq=link.frequency_mhz if link.connected else None,
            ssid=link.ssid if link.connected else None,
            rssi=link.rssi if link.connected else None,
            **fields,
        )
        parts = [f"({self.mac})"]
        if link.bssid:
            parts.append(f"bssid: ({link.bssid})")
        if link.connected:
            parts.append(f"freq: ({link.frequency_mhz})")
            if link.ssid:
                parts.append(f"ssid: ({link.ssid_text})")
            parts.append(f"rssi: ({link.rssi})")
        parts.append(f"event: ({event})")
        return EventLine(", ".join(parts) + extra, record)

    def link_extra(self, link: LinkInfo) -> tuple[str, dict]:
        if not link.connected:
            return "", {}
        extra = f", channel: ({_channel(link)})"
        fields: dict[str, Any] = _channel_json(link)
        if link.tx_rate_mbps is not None:
            extra += f", tx_rate: ({link.tx_rate_mbps:g} Mbps)"
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
        extra += f", old_bssid: ({old.bssid})"
        fields["old_bssid"] = old.bssid
        if old.frequency_mhz != link.frequency_mhz:
            extra += f", old_freq: ({old.frequency_mhz})"
            fields["old_freq_mhz"] = old.frequency_mhz or None
        extra += f", old_rssi: ({old.rssi})"
        fields["old_rssi"] = old.rssi
        if _channel(old) != _channel(link):
            extra += f", old_channel: ({_channel(old)})"
            fields.update(_channel_json(old, "old_"))
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
        if _channel(old) == _channel(link):
            return None
        return self.line(
            link,
            "channel_change",
            f", channel: ({_channel(link)}), old_channel: ({_channel(old)})",
            **_channel_json(link),
            **_channel_json(old, "old_"),
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
        if getattr(self.args, "syslog", None):  # syslog always gets the text
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
            # a station interface that appeared after the watch started
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
        if cmd == nl.CMD_CH_SWITCH_NOTIFY:
            link = self._link(native)
            freq = nl.get_uint(message.attrs, nl.ATTR_WIPHY_FREQ)
            if freq:
                link.frequency_mhz = freq
            width = nl.get_uint(message.attrs, nl.ATTR_CHANNEL_WIDTH)
            if width is not None:
                link.width_mhz = nl.CHAN_WIDTH_MHZ.get(width, link.width_mhz)
            line = formatter.channel_change(link)
            return [line] if line else []
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
