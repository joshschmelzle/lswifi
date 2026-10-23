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
lswifi.backends.macos_events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

--watchevents on macOS.

Two sources, neither needs root:

- CoreWLAN CWEventDelegate callbacks (power, SSID, BSSID, link, link
  quality, mode, country code, scan cache). On every callback the current
  CWInterface state is read and compared to the last state printed, so the
  bursts CoreWLAN sends for one roam or join print as one line.
- airportd's unified log (``log stream``), best effort, for what CoreWLAN
  does not report: roam triggers, deauth/disassoc reason codes and join
  timing, and system sleep/wake and lid markers (macOS powers Wi-Fi down
  in sleep, so a disconnect/connect pair on wake is expected). ``log
  stream`` needs an admin account; if it cannot start, one info line says
  so and the CoreWLAN events still print.

scan_cache_updated lines (several a minute on macOS) print only with
--debug.

The design follows the iairport Swift rewrite (MIT,
github.com/samwiseg0/iAirport): CoreWLAN events for state, airportd log
markers for the why. Everything except MacOSEventWatcher.run() is plain
Python so it is unit tested with fakes on any OS.
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from lswifi.watchjson import event_record, shared_writer, watch_json_requested

log = logging.getLogger(__name__)

# CWEventType, as in the macOS 26 SDK (PyObjC 12)
CW_EVENT_TYPES = {
    "power": 1,
    "ssid": 2,
    "bssid": 3,
    "country_code": 4,
    "link": 5,
    "link_quality": 6,
    "mode": 7,
    "scan_cache": 8,
}

# print a link quality line only when RSSI moved this much since the last
# printed value, or the Tx rate changed by this fraction, and not more often
# than LQ_MIN_INTERVAL seconds
LQ_RSSI_DELTA_DB = 5
LQ_RATE_DELTA = 0.25
LQ_MIN_INTERVAL = 2.0
# same event, same state, within this window: squelch (CoreWLAN repeats)
REPEAT_WINDOW = 2.0

LOG_STREAM_COMMAND = [
    "/usr/bin/log",
    "stream",
    "--predicate",
    'process == "airportd"',
    "--info",
    "--style",
    "compact",
]

# IEEE 802.11-2020 Table 9-49, reason codes
REASON_CODES = {
    1: "unspecified",
    2: "previous authentication no longer valid",
    3: "deauthenticated because STA is leaving",
    4: "disassociated due to inactivity",
    5: "AP unable to handle all associated STAs",
    6: "class 2 frame from nonauthenticated STA",
    7: "class 3 frame from nonassociated STA",
    8: "disassociated because STA is leaving",
    9: "STA requesting association is not authenticated",
    10: "power capability element is unacceptable",
    11: "supported channels element is unacceptable",
    12: "BSS transition management",
    13: "invalid element",
    14: "message integrity code (MIC) failure",
    15: "4-way handshake timeout",
    16: "group key handshake timeout",
    17: "element in 4-way handshake differs",
    18: "invalid group cipher",
    19: "invalid pairwise cipher",
    20: "invalid AKMP",
    21: "unsupported RSNE version",
    22: "invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "cipher suite rejected by security policy",
    32: "unspecified QoS-related reason",
    33: "QoS AP lacks sufficient bandwidth",
    34: "excessive frames not acknowledged",
    35: "STA transmitting outside TXOP limits",
    36: "requesting STA is leaving the BSS",
    37: "requesting STA no longer using the mechanism",
    38: "setup required for the mechanism",
    39: "request timeout",
    45: "peer STA does not support the cipher suite",
    46: "authorized access limit reached",
    47: "external service requirements",
    48: "invalid FT action frame count",
    49: "invalid PMKID",
    50: "invalid MDE",
    51: "invalid FTE",
    58: "poor channel conditions",
    59: "BSS transition disassociation imminent",
    60: "BSS transition excessive frame loss",
    61: "BSS transition excessive delay",
    62: "BSS transition candidate rejected",
    65: "fast transition rejected by AP",
    66: "authentication rejected, anti-clogging token required",
}


def reason_text(code: int) -> str:
    return REASON_CODES.get(code, "reserved/unknown")


@dataclass(frozen=True)
class LinkState:
    """What CoreWLAN reports for the interface at one moment"""

    power: bool = False
    connected: bool = False
    ssid: str = ""
    bssid: str = ""
    channel: int | None = None
    band: str | None = None
    width_mhz: int | None = None
    frequency_mhz: int = 0
    rssi: int | None = None
    noise: int | None = None
    tx_rate: float | None = None
    mode: int = 0
    country_code: str = ""
    # raw SSID octets, for ssid_hex in --json when they are not UTF-8
    ssid_bytes: bytes = field(default=b"", compare=False)

    @property
    def redacted(self) -> bool:
        """associated, but Location Services withheld SSID and BSSID"""
        return self.connected and not self.bssid


def read_link_state(cw_iface) -> LinkState:
    """Snapshot a CWInterface (or anything shaped like one)"""
    from lswifi.backends.macos import (
        BAND_NAMES,
        CW_CHANNEL_WIDTH_MHZ,
        _nsdata_bytes,
        frequency_from_channel,
    )

    power = bool(cw_iface.powerOn())
    mode = int(cw_iface.interfaceMode() or 0) if power else 0
    connected = power and bool(mode)
    channel = cw_iface.wlanChannel() if connected else None
    number = channel.channelNumber() if channel is not None else None
    band = channel.channelBand() if channel is not None else None
    width = channel.channelWidth() if channel is not None else None
    rssi = cw_iface.rssiValue() if connected else None
    noise = cw_iface.noiseMeasurement() if connected else None
    rate = cw_iface.transmitRate() if connected else None
    ssid_bytes = _nsdata_bytes(cw_iface.ssidData()) if connected else b""
    return LinkState(
        power=power,
        connected=connected,
        ssid=ssid_bytes.decode("utf-8", errors="replace"),
        ssid_bytes=ssid_bytes,
        bssid=str(cw_iface.bssid() or "").lower() if connected else "",
        channel=int(number) if number else None,
        band=BAND_NAMES.get(band) if band is not None else None,
        width_mhz=CW_CHANNEL_WIDTH_MHZ.get(width) if width else None,
        frequency_mhz=frequency_from_channel(int(number), band) if number else 0,
        rssi=int(rssi) if rssi else None,
        noise=int(noise) if noise else None,
        tx_rate=float(rate) if rate else None,
        mode=mode,
        country_code=str(cw_iface.countryCode() or ""),
    )


class EventLine(str):
    """A --watchevents text line that also carries its --json record"""

    record: dict

    def __new__(cls, text: str, record: dict | None = None) -> "EventLine":
        line = super().__new__(cls, text)
        line.record = record or {}
        return line


def _channel_json(state: LinkState, prefix: str = "") -> dict:
    return {
        f"{prefix}channel": state.channel,
        f"{prefix}width_mhz": state.width_mhz,
        f"{prefix}band": state.band,
    }


def _channel(state: LinkState) -> str:
    if state.channel is None:
        return ""
    parts = [str(state.channel)]
    if state.width_mhz:
        parts[0] += f"@{state.width_mhz}"
    if state.band:
        parts.append(state.band)
    return " ".join(parts)


class EventFormatter:
    """Turns successive LinkStates into Windows-style --watchevents lines"""

    def __init__(self, mac: str, clock: Callable[[], float] = time.monotonic):
        self.mac = mac
        self.clock = clock
        self.last: LinkState | None = None
        # last snapshot that had a BSSID: CoreWLAN can report a nil BSSID for
        # a moment mid-roam, and the roam must still compare against the old AP
        self.last_link: LinkState | None = None
        self.last_lq: LinkState | None = None
        self.last_lq_time = 0.0
        self.last_line = ""
        self.last_line_time = 0.0
        self.location_warning_needed = False

    def _fields(
        self, state: LinkState, extra: str = "", event: str = "", **fields: Any
    ) -> EventLine:
        """The text line, plus the same values as a --json record"""
        if state.redacted:
            self.location_warning_needed = True
            fields["location_redacted"] = True
        record = event_record(
            self.mac,
            event,
            bssid=state.bssid,
            freq=state.frequency_mhz if state.connected else None,
            ssid=(state.ssid_bytes or state.ssid) if state.connected else None,
            rssi=state.rssi if state.connected else None,
            **fields,
        )
        parts = [f"({self.mac})"]
        if state.bssid:
            parts.append(f"bssid: ({state.bssid})")
        if state.connected:
            parts.append(f"freq: ({state.frequency_mhz})")
            if state.ssid:
                parts.append(f"ssid: ({state.ssid})")
            parts.append(f"rssi: ({state.rssi})")
        parts.append(f"event: ({event})")
        return EventLine(", ".join(parts) + extra, record)

    def _link_json(self, state: LinkState) -> dict:
        if not state.connected:
            return {}
        return {
            **_channel_json(state),
            "noise": state.noise,
            "tx_rate_mbps": state.tx_rate,
        }

    def _link_extra(self, state: LinkState) -> str:
        if not state.connected:
            return ""
        extra = f", channel: ({_channel(state)})"
        if state.noise is not None:
            extra += f", noise: ({state.noise})"
        if state.tx_rate is not None:
            extra += f", tx_rate: ({state.tx_rate:g} Mbps)"
        return extra

    def _roam(self, old: LinkState, new: LinkState) -> EventLine:
        """Same leading fields as every other line (new values), then old_* fields"""
        fields: dict[str, Any] = _channel_json(new)
        extra = f", channel: ({_channel(new)})"
        if new.tx_rate:
            extra += f", tx_rate: ({new.tx_rate:g} Mbps)"
            fields["tx_rate_mbps"] = new.tx_rate
        extra += f", old_bssid: ({old.bssid})"
        fields["old_bssid"] = old.bssid
        if old.frequency_mhz != new.frequency_mhz:
            extra += f", old_freq: ({old.frequency_mhz})"
            fields["old_freq_mhz"] = old.frequency_mhz or None
        extra += f", old_rssi: ({old.rssi})"
        fields["old_rssi"] = old.rssi
        if _channel(old) != _channel(new):
            extra += f", old_channel: ({_channel(old)})"
            fields.update(_channel_json(old, "old_"))
        return self._fields(new, extra, "roamed", **fields)

    def state_change(self, new: LinkState) -> list[EventLine]:
        """Lines for whatever changed since the last state printed"""
        old = self.last
        self.last = new
        known = self.last_link
        if new.connected and new.bssid:
            self.last_link = new
        if old is None:
            self.last_lq, self.last_lq_time = new, self.clock()
            return [
                self._fields(
                    new, self._link_extra(new), "watching", **self._link_json(new)
                )
            ]
        lines = []
        if old.power != new.power:
            lines.append(self._fields(new, "", "power_on" if new.power else "power_off"))
            if not new.power:
                return lines
        if old.connected and not new.connected:
            gone = old if old.bssid or known is None else known
            lines.append(self._fields(gone, "", "disconnected"))
        elif new.connected and not old.connected:
            extra, fields = self._link_extra(new), self._link_json(new)
            if known and known.bssid and new.bssid and known.bssid != new.bssid:
                # a reconnect to a different AP (not a roam: the link went down)
                extra += f", old_bssid: ({known.bssid})"
                fields["old_bssid"] = known.bssid
            lines.append(self._fields(new, extra, "connected", **fields))
            if not new.bssid:
                # BSSID not known yet: do not call its later arrival a roam
                self.last_link = None
        elif new.connected and old.bssid and not new.bssid:
            pass  # nil BSSID mid-roam; wait for the next snapshot
        elif new.connected:
            if not old.bssid and new.bssid and known is not None:
                old = known  # BSSID is back after a nil burst
            if old.bssid and new.bssid and old.bssid != new.bssid:
                lines.append(self._roam(old, new))
            elif old.ssid and new.ssid and old.ssid != new.ssid:
                lines.append(
                    self._fields(
                        new,
                        f", old_ssid: ({old.ssid})",
                        "ssid_change",
                        old_ssid=old.ssid,
                    )
                )
            elif old.channel != new.channel or old.width_mhz != new.width_mhz:
                lines.append(
                    self._fields(
                        new,
                        f", channel: ({_channel(new)}), old_channel: ({_channel(old)})",
                        "channel_change",
                        **_channel_json(new),
                        **_channel_json(old, "old_"),
                    )
                )
            elif old.mode != new.mode:
                lines.append(
                    self._fields(
                        new,
                        f", mode: ({new.mode}), old_mode: ({old.mode})",
                        "mode_change",
                        mode=new.mode,
                        old_mode=old.mode,
                    )
                )
        if old.country_code != new.country_code and new.power:
            lines.append(
                self._fields(
                    new,
                    f", country_code: ({new.country_code or '--'}), old_country_code: ({old.country_code or '--'})",
                    "country_code_change",
                    country_code=new.country_code,
                    old_country_code=old.country_code,
                )
            )
        if lines:
            # a roam or join resets the link-quality baseline
            self.last_lq, self.last_lq_time = new, self.clock()
        return lines

    def link_quality(self, new: LinkState) -> list[EventLine]:
        """A signal_quality_change line, only for a meaningful change"""
        if not new.connected or new.rssi is None:
            return []
        now = self.clock()
        base = self.last_lq
        if base is not None and base.bssid == new.bssid:
            if now - self.last_lq_time < LQ_MIN_INTERVAL:
                return []
            rssi_moved = base.rssi is None or abs(new.rssi - base.rssi) >= LQ_RSSI_DELTA_DB
            rate_moved = bool(
                base.tx_rate
                and new.tx_rate
                and abs(new.tx_rate - base.tx_rate) / base.tx_rate >= LQ_RATE_DELTA
            )
            if not (rssi_moved or rate_moved):
                return []
        self.last_lq, self.last_lq_time = new, now
        extra = ""
        fields: dict[str, Any] = {}
        if base is not None and base.rssi is not None:
            extra += f", old_rssi: ({base.rssi})"
            fields["old_rssi"] = base.rssi
        if new.tx_rate is not None:
            extra += f", tx_rate: ({new.tx_rate:g} Mbps)"
            fields["tx_rate_mbps"] = new.tx_rate
        return [self._fields(new, extra, "signal_quality_change", **fields)]

    def scan_cache(self, state: LinkState, count: int) -> list[EventLine]:
        return [
            self._fields(
                state,
                f", scan: ({count} BSSIDs found)",
                "scan_cache_updated",
                scan_bssid_count=count,
            )
        ]

    def squelch(self, line: str) -> bool:
        """True for an identical line inside REPEAT_WINDOW"""
        now = self.clock()
        key = line.split(", event: ")[-1]
        repeat = key == self.last_line and now - self.last_line_time < REPEAT_WINDOW
        self.last_line, self.last_line_time = key, now
        return repeat


# airportd log markers; BSSIDs in these lines are <redacted>
_DEAUTH = re.compile(
    r"Received (Deauth|Disassoc) from (<redacted>|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) with Reason (\d+)"
)
_TIMING = re.compile(
    r"\b(assoc|auth|linkup|ipv4|ipv4Primary|ipv6|ipv6Primary)=[^(]*\((\d+)ms\)"
)
_JOIN_UUID = re.compile(r"uuid=([^,)\s]+)")
# "Roam: <airport[423]> -[CWXPCInterfaceContext __trigger...]: BEST CONNECTED ROAM triggered"
_ROAM_TRIGGER = re.compile(r"(?:\]:|>)\s*([A-Z][A-Z0-9 _-]*?)\s+ROAM triggered(.*)$")
# "...: Requesting Roam : {" then "    KEY = value;" lines then "}"
_ROAM_REQUEST = "Requesting Roam : {"
_ROAM_BLOCK_ITEM = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?);?\s*$")
_NSDATA_BYTES = re.compile(r"bytes\s*=\s*0x([0-9A-Fa-f]{12})")
# a new unified log entry (compact style) starts with a timestamp
# only the target channel itself; not CHANNEL_FLAGS and friends
_ROAM_CHANNEL_KEYS = frozenset({"CHANNEL", "ROAM_CHANNEL", "ROAMTOCHANNEL", "ROAM_TO_CHANNEL"})
_TRIGGER_REASON = re.compile(r"reason\s*[=:]\s*([A-Za-z0-9_]+)")
_LOG_ENTRY = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_WAKE = re.compile(r"airportdProcessWake: Received (dark|full) wake event")
_CLAMSHELL = re.compile(r"Clamshell state changed \(closed=(\d)")
# the same airportd marker logged twice within this window prints once
LOG_REPEAT_WINDOW = 2.0
_TIMING_ORDER = ["assoc", "auth", "linkup", "ipv4", "ipv6", "ipv4Primary", "ipv6Primary"]


def _snake(name: str) -> str:
    """ipv4Primary -> ipv4_primary"""
    return re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "_" + m.group(1).lower(), name)


@dataclass
class LogEvent:
    event: str
    detail: str
    # the same values for --json (reason_code, assoc_ms, ...)
    fields: dict = field(default_factory=dict, compare=False)


def _one_line(text: str, limit: int = 160) -> str:
    """Never let log text put a newline (or a run of spaces) in an event line"""
    return " ".join(text.split())[:limit]


def _roam_target_bssid(value: str) -> str | None:
    match = _NSDATA_BYTES.search(value)
    if not match:
        return None
    raw = match.group(1).lower()
    if raw in ("ffffffffffff", "000000000000"):
        return "any"  # no target: let the driver pick the best BSS
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


class AirportdLogClassifier:
    """Picks the few airportd lines worth a --watchevents line

    ``feed()`` takes raw ``log stream`` lines, including the continuation
    lines of multi-line messages (the "Requesting Roam : { ... }" block), and
    returns finished events. ``classify()`` handles one complete line.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.seen_joins: set[str] = set()
        self.pending_trigger: str | None = None
        self.pending_reason: str | None = None
        self.roam_block: list[str] | None = None
        self.last_marker = ""
        self.last_marker_time = 0.0

    def feed(self, line: str) -> list[LogEvent]:
        line = line.rstrip("\r\n")
        events: list[LogEvent] = []
        if self.roam_block is not None:
            if not _LOG_ENTRY.match(line):
                if line.strip().startswith("}"):
                    events.append(self._roam_request(self.roam_block))
                    self.roam_block = None
                else:
                    self.roam_block.append(line)
                return events
            # a new entry before the closing brace: emit what we have
            events.append(self._roam_request(self.roam_block))
            self.roam_block = None
        elif not _LOG_ENTRY.match(line) and line[:1].isspace():
            return events  # continuation of a message we do not parse
        if _ROAM_REQUEST in line:
            rest = line.split(_ROAM_REQUEST, 1)[1]
            if "}" in rest:  # whole block on one line
                # NSData values like BSSID carry their own {...}; the block ends at the last }
                events.append(self._roam_request(rest.rsplit("}", 1)[0].split(";")))
            else:
                self.roam_block = [rest] if rest.strip() else []
            return events
        if self.pending_trigger is not None:
            # a trigger with no "Requesting Roam" right after it
            events.append(self._roam_triggered(self.pending_trigger))
            self.pending_trigger = None
        trigger = _ROAM_TRIGGER.search(line)
        if trigger:
            name = "_".join(trigger.group(1).lower().replace("-", " ").split())
            self.pending_trigger = f"{name}_roam"
            reason = _TRIGGER_REASON.search(trigger.group(2))
            self.pending_reason = reason.group(1) if reason else None
            return events
        event = self.classify(line)
        if event is not None:
            events.append(event)
        return events

    def flush(self) -> list[LogEvent]:
        """Whatever a roam block or trigger still holds (end of stream)"""
        events = []
        if self.roam_block is not None:
            events.append(self._roam_request(self.roam_block))
            self.roam_block = None
        elif self.pending_trigger is not None:
            events.append(self._roam_triggered(self.pending_trigger))
        self.pending_trigger = self.pending_reason = None
        return events

    def _trigger_parts(self, parts: list[str], fields: dict[str, Any]) -> None:
        if self.pending_trigger is not None:
            parts.append(f"trigger: ({self.pending_trigger})")
            fields["trigger"] = self.pending_trigger
        if self.pending_reason:
            parts.append(f"roam_reason: ({self.pending_reason})")
            fields["roam_reason"] = self.pending_reason
        self.pending_trigger = self.pending_reason = None

    def _roam_triggered(self, trigger: str) -> LogEvent:
        parts: list[str] = []
        fields: dict[str, Any] = {}
        self._trigger_parts(parts, fields)
        return LogEvent("roam_triggered", ", ".join(parts), fields)

    def _roam_request(self, items: list[str]) -> LogEvent:
        parts: list[str] = []
        fields: dict[str, Any] = {}
        self._trigger_parts(parts, fields)
        for item in items:
            match = _ROAM_BLOCK_ITEM.match(item)
            if not match:
                continue
            key, value = match.group(1).upper(), match.group(2).strip()
            if key == "BSSID":
                bssid = _roam_target_bssid(value)
                if bssid:
                    parts.append(f"roam_target_bssid: ({bssid})")
                    fields["roam_target_bssid"] = bssid
            elif (
                key in _ROAM_CHANNEL_KEYS
                and value.isdigit()
                and "roam_target_channel" not in fields
            ):
                parts.append(f"roam_target_channel: ({value})")
                fields["roam_target_channel"] = int(value)
            elif "REASON" in key and "roam_reason" not in fields:
                reason = _one_line(value.strip('"'), 60)
                parts.append(f"roam_reason: ({reason})")
                fields["roam_reason"] = int(reason) if reason.isdigit() else reason
        return LogEvent("roam_requested", ", ".join(parts), fields)

    def _repeat(self, marker: str) -> bool:
        """airportd logs sleep/wake markers twice; print the first"""
        now = self.clock()
        repeat = marker == self.last_marker and now - self.last_marker_time < LOG_REPEAT_WINDOW
        self.last_marker, self.last_marker_time = marker, now
        return repeat

    def classify(self, line: str) -> LogEvent | None:
        line = line.rstrip("\r\n")
        match = _DEAUTH.search(line)
        if match:
            kind, source, code = match.group(1), match.group(2), int(match.group(3))
            detail = f"reason: ({code} {reason_text(code)})"
            fields: dict[str, Any] = {}
            if source != "<redacted>":
                detail = f"from: ({source.lower()}), " + detail
                fields["from_bssid"] = source.lower()
            fields.update(reason_code=code, reason_text=reason_text(code))
            return LogEvent(
                "deauth" if kind == "Deauth" else "disassoc", detail, fields
            )
        if "_acknowledgeSleepEvent: Acknowledging sleep event" in line:
            # the Mac is going to sleep; Wi-Fi powers down until the next wake
            if self._repeat("sleep"):
                return None
            return LogEvent("system_sleep", "", {})
        wake = _WAKE.search(line)
        if wake:
            kind = wake.group(1)
            if self._repeat(f"wake:{kind}"):
                return None
            return LogEvent("system_wake", f"wake: ({kind})", {"wake": kind})
        clamshell = _CLAMSHELL.search(line)
        if clamshell:
            event = "lid_closed" if clamshell.group(1) == "1" else "lid_opened"
            if self._repeat(event):
                return None
            return LogEvent(event, "", {})
        if "AUTO-JOIN: Updated join status" in line:
            values = dict(_TIMING.findall(line))
            if not all(key in values for key in ("assoc", "auth", "linkup")):
                return None
            uuid_match = _JOIN_UUID.search(line)
            key = uuid_match.group(1) if uuid_match else ",".join(values.values())
            if key in self.seen_joins:
                return None
            self.seen_joins.add(key)
            timing = ", ".join(
                f"{name}: ({values[name]} ms)" for name in _TIMING_ORDER if name in values
            )
            return LogEvent(
                "join_timing",
                timing,
                {
                    _snake(name) + "_ms": int(values[name])
                    for name in _TIMING_ORDER
                    if name in values
                },
            )
        return None


class AirportdLogReader:
    """Best-effort ``log stream`` of airportd on a daemon thread"""

    def __init__(
        self,
        on_event: Callable[[LogEvent], None],
        popen: Callable[..., Any] = subprocess.Popen,
    ) -> None:
        self.on_event = on_event
        self.popen = popen
        self.classifier = AirportdLogClassifier()
        self.process: Any = None
        self.thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            self.process = self.popen(
                LOG_STREAM_COMMAND,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1,
            )
        except OSError as error:
            log.info("airportd log events unavailable (%s); CoreWLAN events only", error)
            return False
        self.thread = threading.Thread(target=self._read, name="airportd-log", daemon=True)
        self.thread.start()
        return True

    def _read(self) -> None:
        process = self.process  # stop() clears self.process
        last = ""
        try:
            for line in process.stdout:
                last = line.strip() or last
                for event in self.classifier.feed(line):
                    self.on_event(event)
            for event in self.classifier.flush():
                self.on_event(event)
            code = process.wait()
        except (OSError, ValueError):  # pipe closed during shutdown
            return
        if self.process is None:  # stopped on purpose
            return
        if code not in (0, None, -2, -15):
            log.info(
                "airportd log events unavailable (log stream exited %s: %s); "
                "CoreWLAN events only. log stream needs an admin account.",
                code,
                last[:200],
            )

    def stop(self) -> None:
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


_delegate_class: Any = None


def _make_delegate_class():
    """Define the CWEventDelegate NSObject subclass once per process"""
    global _delegate_class
    if _delegate_class is not None:
        return _delegate_class
    import objc  # type: ignore[import-not-found,import-untyped]
    from Foundation import NSObject  # type: ignore[import-not-found,import-untyped]

    protocol = objc.protocolNamed("CWEventDelegate")

    class LswifiCWEventDelegate(NSObject, protocols=[protocol]):  # type: ignore[misc,call-arg]
        def initWithWatcher_(self, watcher):
            self = objc.super(LswifiCWEventDelegate, self).init()
            if self is None:
                return None
            self.watcher = watcher
            return self

        def powerStateDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("power", name)

        def ssidDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("ssid", name)

        def bssidDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("bssid", name)

        def linkDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("link", name)

        def modeDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("mode", name)

        def countryCodeDidChangeForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("country_code", name)

        def scanCacheUpdatedForWiFiInterfaceWithName_(self, name):
            self.watcher.on_event("scan_cache", name)

        @objc.typedSelector(b"v@:@qd")
        def linkQualityDidChangeForWiFiInterfaceWithName_rssi_transmitRate_(
            self, name, rssi, rate
        ):
            self.watcher.on_event("link_quality", name)

        def clientConnectionInterrupted(self):
            self.watcher.on_connection_lost("interrupted")

        def clientConnectionInvalidated(self):
            self.watcher.on_connection_lost("invalidated")

    _delegate_class = LswifiCWEventDelegate
    return _delegate_class


class MacOSEventWatcher:
    """Prints --watchevents lines for every Wi-Fi interface"""

    def __init__(
        self,
        client,
        interfaces: list,
        args,
        emit: Callable[[EventLine], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.args = args
        self.lock = threading.RLock()
        self.interfaces = {info.connection_name: info for info in interfaces}
        self.formatters = {
            info.connection_name: EventFormatter(info.mac, clock) for info in interfaces
        }
        self.emit = emit or self._emit
        # --watchevents --json: NDJSON records on stdout instead of log lines
        self.json_writer = shared_writer() if watch_json_requested(args) else None
        # macOS refreshes its scan cache several times a minute; those lines
        # bury the real events, so they print only with --debug
        self.scan_events = getattr(args, "debug", logging.INFO) == logging.DEBUG
        self.log_reader: AirportdLogReader | None = None
        self.delegate: Any = None

    def _emit(self, line: str) -> None:
        record = getattr(line, "record", None)
        if self.json_writer is not None and record is not None:
            self.json_writer.write(record)
        else:
            log.info(line)
        if getattr(self.args, "syslog", None):  # syslog always gets the text
            from lswifi.slog import message as syslog

            syslog(line, "INFO")

    def _cw_iface(self, name: str):
        info = self.interfaces[name]
        return info.native if info.native is not None else self.client.interfaceWithName_(name)

    def _print(self, formatter: EventFormatter, lines: list[EventLine]) -> None:
        for line in lines:
            if not formatter.squelch(line):
                self.emit(line)
        if formatter.location_warning_needed:
            from lswifi.backends.macos import warn_location_once

            warn_location_once()

    def on_event(self, kind: str, name=None) -> None:
        """CWEventDelegate callback; any thread"""
        try:
            name = str(name) if name else next(iter(self.interfaces), "")
            if name not in self.interfaces:
                return
            with self.lock:
                formatter = self.formatters[name]
                cw_iface = self._cw_iface(name)
                state = read_link_state(cw_iface)
                if kind == "link_quality":
                    lines = formatter.link_quality(state)
                elif kind == "scan_cache":
                    # still compare state: a scan callback can be the first
                    # sign of a join or roam
                    lines = formatter.state_change(state)
                    if self.scan_events:
                        cached = cw_iface.cachedScanResults()
                        lines += formatter.scan_cache(state, len(cached or ()))
                else:
                    lines = formatter.state_change(state)
                self._print(formatter, lines)
        except Exception:  # never let a callback kill the run loop
            log.exception("error handling CoreWLAN %s event", kind)

    def on_log_event(self, event: LogEvent) -> None:
        """airportd log line; the reader thread"""
        with self.lock:
            for name, formatter in self.formatters.items():
                state = formatter.last or LinkState()
                text = f"({formatter.mac}), "
                if state.bssid:
                    text += f"bssid: ({state.bssid}), "
                text += f"event: ({event.event})"
                if event.detail:
                    text += f", {event.detail}"
                record = event_record(
                    formatter.mac, event.event, bssid=state.bssid, **event.fields
                )
                self.emit(EventLine(text, record))
                break  # airportd lines do not say which interface; use the first

    def on_connection_lost(self, why: str) -> None:
        log.warning("CoreWLAN event connection %s; re-registering", why)
        self.start_monitoring()

    def start_monitoring(self) -> list[str]:
        """Register for every CWEventType; returns the ones that failed"""
        failed = []
        for kind, value in CW_EVENT_TYPES.items():
            result = self.client.startMonitoringEventWithType_error_(value, None)
            ok, error = result if isinstance(result, tuple) else (result, None)
            if not ok:
                failed.append(kind)
                log.debug("startMonitoringEventWithType %s failed: %s", kind, error)
        return failed

    def start(self, with_log_stream: bool = True) -> None:
        for name in self.interfaces:
            self.on_event("watching", name)
        self.delegate = _make_delegate_class().alloc().initWithWatcher_(self)
        self.client.setDelegate_(self.delegate)
        failed = self.start_monitoring()
        if len(failed) == len(CW_EVENT_TYPES):
            raise RuntimeError("CoreWLAN refused every event subscription")
        if failed:
            log.info("CoreWLAN events not available here: %s", ", ".join(failed))
        if with_log_stream:
            self.log_reader = AirportdLogReader(self.on_log_event)
            self.log_reader.start()

    def stop(self) -> None:
        if self.log_reader is not None:
            self.log_reader.stop()
        try:
            self.client.stopMonitoringAllEventsAndReturnError_(None)
        except Exception:
            log.debug("stopMonitoringAllEvents failed", exc_info=True)
        self.client.setDelegate_(None)

    def run(self) -> None:
        """Block on the main run loop until Ctrl-C"""
        from Foundation import NSDate, NSRunLoop  # type: ignore[import-not-found,import-untyped]

        self.start()
        try:
            loop = NSRunLoop.currentRunLoop()
            while True:
                # short slices so KeyboardInterrupt is seen promptly
                loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.5))
        finally:
            self.stop()


__all__ = [
    "AirportdLogClassifier",
    "AirportdLogReader",
    "EventFormatter",
    "EventLine",
    "LinkState",
    "LogEvent",
    "MacOSEventWatcher",
    "read_link_state",
    "reason_text",
]
