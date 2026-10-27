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
handshake done), channel switch, rejected or timed-out authentication and
timed-out association events, so nothing is polled. A link
added or removed, and a channel switch that names a link, are reported for
that link. Scan started, scan complete and scan aborted print by default.
A locally generated disconnect followed by a connect on the same SSID stays
those two events; the connect carries whether it was a roam, the roam type
and how long it took. Lines use the same layout and --json schema as the
Windows and macOS watchers.
"""

import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

from lswifi.backends import nl80211 as nl
from lswifi.backends.base import BackendError, InterfaceInfo
from lswifi.backends.linux import (
    LinkInfo,
    LinuxInterface,
    _choose_link,
    _public_link,
    band_name,
    channel_number,
    parse_mlo_links,
)
from lswifi.backends.macos_events import EventLine, reason_text
from lswifi.helpers import format_mbps
from lswifi.watchjson import event_record, shared_writer, watch_json_requested

log = logging.getLogger(__name__)

_MISSING: Any = object()

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


# A locally generated disconnect and the connect that follows, same SSID.
ROAM_WINDOW_S = 2.0

# 802.11 Authentication algorithm numbers (frame body). Not nl80211 AUTH_TYPE.
AUTH_OPEN = 0
AUTH_FT = 2
AUTH_SAE = 3

EID_RSN = 48
EID_FAST_BSS_TRANSITION = 55

_FC_TYPE_MASK = 0x000C
_FC_SUBTYPE_SHIFT = 4
_FC_SUBTYPE_MASK = 0x000F
_FC_PROTECTED = 0x4000
_FC_ORDER = 0x8000
_MGMT_HEADER = 24
_HT_CONTROL = 4
_AUTH_SUBTYPE = 0xB

STATUS_SUCCESS = 0
STATUS_ANTI_CLOGGING_TOKEN_REQUIRED = 76
STATUS_SAE_HASH_TO_ELEMENT = 126
STATUS_SAE_PK = 127
AUTH_CONTINUE_STATUS = frozenset(
    {
        STATUS_SUCCESS,
        STATUS_ANTI_CLOGGING_TOKEN_REQUIRED,
        STATUS_SAE_HASH_TO_ELEMENT,
        STATUS_SAE_PK,
    }
)


def _elapsed_ms(start: float, end: float) -> int:
    return max(0, round((end - start) * 1000))


def _auth_body(frame: bytes) -> bytes | None:
    if len(frame) < _MGMT_HEADER + 2:
        return None
    fc = int.from_bytes(frame[:2], "little")
    if fc & _FC_TYPE_MASK:
        return None
    subtype = (fc >> _FC_SUBTYPE_SHIFT) & _FC_SUBTYPE_MASK
    if subtype != _AUTH_SUBTYPE:
        return None
    if fc & _FC_PROTECTED:
        return None
    offset = _MGMT_HEADER + (_HT_CONTROL if fc & _FC_ORDER else 0)
    if len(frame) < offset + 2:
        return None
    return frame[offset:]


def auth_algorithm(frame: bytes) -> int | None:
    """Authentication algorithm from a CMD_AUTHENTICATE ATTR_FRAME.

    The kernel sends the received Authentication frame (header and body, no
    FCS). Open is 0, FT is 2 and SAE is 3. nl80211 ATTR_AUTH_TYPE is a
    different enum and is not included on this event.
    """
    body = _auth_body(frame)
    return None if body is None else int.from_bytes(body[:2], "little")


def auth_failure(frame: bytes) -> tuple[str, int] | None:
    body = _auth_body(frame)
    if body is None or len(body) < 6:
        return None
    status = int.from_bytes(body[4:6], "little")
    if status in AUTH_CONTINUE_STATUS:
        return None
    return nl.mac_str(frame[10:16]), status


def _elements(buf: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 2 <= len(buf):
        eid = buf[offset]
        length = buf[offset + 1]
        offset += 2
        if offset + length > len(buf):
            return
        yield eid, buf[offset : offset + length]
        offset += length


def rsn_pmkid_count(body: bytes) -> int | None:
    """PMKIDs in an RSNE body: 0 when the list is absent, None if truncated."""
    if len(body) < 2:
        return None
    pos = 2
    if pos + 4 > len(body):
        return 0
    pos += 4
    if pos + 2 > len(body):
        return 0
    pairwise = int.from_bytes(body[pos : pos + 2], "little")
    pos += 2
    if pairwise > 20 or pos + 4 * pairwise > len(body):
        return None
    pos += 4 * pairwise
    if pos + 2 > len(body):
        return 0
    akm = int.from_bytes(body[pos : pos + 2], "little")
    pos += 2
    if akm > 20 or pos + 4 * akm > len(body):
        return None
    pos += 4 * akm
    if pos + 2 > len(body):
        return 0
    pos += 2
    if pos + 2 > len(body):
        return 0
    count = int.from_bytes(body[pos : pos + 2], "little")
    pos += 2
    if count > 16 or pos + 16 * count > len(body):
        return None
    return count


def roam_kind(auth_alg: int | None, ies: bytes | None) -> str | None:
    """ft, pmksa, sae, full, or None when the frames do not say."""
    fast = auth_alg == AUTH_FT
    has_rsn = False
    pmkids: int | None = 0
    if ies:
        for eid, body in _elements(ies):
            if eid == EID_FAST_BSS_TRANSITION:
                fast = True
            elif eid == EID_RSN and not has_rsn:
                has_rsn = True
                pmkids = rsn_pmkid_count(body)
    if fast:
        return "ft"
    if auth_alg == AUTH_SAE:
        return "sae"
    if pmkids:
        return "pmksa"
    if auth_alg == AUTH_OPEN and has_rsn and pmkids == 0:
        return "full"
    return None


def scan_frequency_count(attrs: dict[int, bytes]) -> int | None:
    """Channels in ATTR_SCAN_FREQUENCIES, or ATTR_SCAN_FREQ_KHZ when that is used."""
    for kind in (nl.ATTR_SCAN_FREQUENCIES, nl.ATTR_SCAN_FREQ_KHZ):
        raw = attrs.get(kind)
        if raw is None:
            continue
        return sum(len(value) == 4 for _kind, value in nl.iter_attrs(raw))
    return None


def _snapshot(link: LinkInfo) -> dict[str, Any]:
    links = list(link.extra.get("links") or [])
    freq = link.frequency_mhz
    width = link.width_mhz
    channel = link.channel
    band = link.band
    if len(links) > 1 and freq is None:
        assoc = link.extra.get("assoc_link_id")
        assoc_id = assoc if isinstance(assoc, int) else None
        primary = _choose_link(links, assoc_id) or links[0]
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


def _association_id(links: list[dict[str, Any]], assoc_id: int | None = None) -> Any:
    chosen = _choose_link(links, assoc_id)
    if not chosen:
        return None
    return chosen.get("id")


def _previous_mld(link: LinkInfo) -> str | None:
    if not link.bssid:
        return None
    if link.extra.get("links") or link.extra.get("ap_mld"):
        return link.bssid
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
        created: dict[str, Any] = {"id": link_id, "active": None, "stats": None}
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
        self._disc: tuple[float, str, bytes] | None = None
        self._auth_alg: int | None = None
        self._auth_at: float | None = None
        self._req_ies: bytes | None = None
        self._roam_cmd_at: float | None = None
        self._connect_at: float | None = None
        self._roam_origin: float | None = None

    def _recent(self, started: float | None, now: float) -> bool:
        return started is not None and 0 <= now - started <= ROAM_WINDOW_S

    def _clear_auth(self) -> None:
        self._auth_alg = None
        self._auth_at = None
        self._req_ies = None
        self._roam_cmd_at = None

    def observe_mlme(self, attrs: dict[int, bytes]) -> None:
        frame = attrs.get(nl.ATTR_FRAME)
        if frame:
            alg = auth_algorithm(frame)
            if alg is not None:
                if self._auth_at is None:
                    self._auth_at = time.monotonic()
                self._auth_alg = alg
        ies = attrs.get(nl.ATTR_REQ_IE)
        if ies:
            self._req_ies = ies

    def observe_roam(self, attrs: dict[int, bytes]) -> None:
        self._roam_cmd_at = time.monotonic()
        ies = attrs.get(nl.ATTR_REQ_IE)
        if ies:
            self._req_ies = ies

    def _request_ies(self, attrs: dict[int, bytes] | None) -> bytes | None:
        if attrs:
            ies = attrs.get(nl.ATTR_REQ_IE)
            if ies:
                return ies
        return self._req_ies

    def _disconnect_at(self, link: LinkInfo, now: float) -> float | None:
        disc = self._disc
        if disc is None or not self._recent(disc[0], now):
            return None
        started, bssid, ssid = disc
        if not link.bssid or link.bssid.lower() == bssid.lower():
            return None
        if not ssid or bytes(link.ssid) != ssid:
            return None
        return started

    def line(
        self, link: LinkInfo, event: str, extra: str = "", **fields: Any
    ) -> EventLine:
        affected = fields.pop("affected", None)
        mlo_address = fields.pop("_mlo_address", False)
        old_ap_mld = fields.pop("old_ap_mld", _MISSING)
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
        if old_ap_mld is not _MISSING:
            record["old_ap_mld"] = old_ap_mld
        parts = [f"({self.mac})"]
        if link.bssid:
            if mlo_address or (link.connected and snap["links"]):
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
            fields["ap_mld"] = link.bssid
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

    def connected(
        self, link: LinkInfo, attrs: dict[int, bytes] | None = None
    ) -> EventLine:
        now = time.monotonic()
        old, self.last = self.last, link
        extra, fields = self.link_extra(link)
        old_mld = None
        if old.bssid and link.bssid and old.bssid != link.bssid:
            extra += f", old_bssid: ({old.bssid})"
            fields["old_bssid"] = old.bssid
            old_mld = _previous_mld(old)
        if old_mld:
            extra += f", old_ap_mld: ({old_mld})"
        fields["old_ap_mld"] = old_mld
        disc_at = self._disconnect_at(link, now)
        roam = disc_at is not None or self._recent(self._roam_cmd_at, now)
        origin: float | None = None
        if roam:
            if disc_at is not None:
                origin = disc_at
            elif self._recent(self._auth_at, now):
                origin = self._auth_at
            elif self._recent(self._roam_cmd_at, now):
                origin = self._roam_cmd_at
        fields["roam"] = roam
        extra += f", roam: ({'yes' if roam else 'no'})"
        kind = roam_kind(self._auth_alg, self._request_ies(attrs)) if roam else None
        if kind:
            fields["roam_type"] = kind
            extra += f", roam_type: ({kind})"
        if origin is not None:
            elapsed = _elapsed_ms(origin, now)
            fields["roam_ms"] = elapsed
            extra += f", roam_ms: ({elapsed})"
        self._connect_at = now
        self._roam_origin = origin
        self._disc = None
        self._clear_auth()
        return self.line(link, "connected", extra, **fields)

    def connect_failed(self, bssid: str, status: int, timed_out: bool) -> EventLine:
        old = self.last
        if old.connected and old.bssid and self._disc is None:
            self._disc = (time.monotonic(), old.bssid, bytes(old.ssid))
        kept: dict[str, Any] = {}
        previous = _previous_mld(self.last)
        if previous:
            kept["ap_mld"] = previous
        self.last = LinkInfo(bssid=self.last.bssid, extra=kept)
        self._clear_auth()
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

    def mlme_failed(
        self, event: str, bssid: str, status: int | None, timed_out: bool
    ) -> EventLine:
        extra = ""
        fields: dict[str, Any] = {}
        if status is not None:
            extra += f", status: ({status} {status_text(status)})"
            fields.update(status_code=status, status_text=status_text(status))
        if timed_out:
            extra += ", timed_out: (yes)"
            fields["timed_out"] = True
        return self.line(LinkInfo(bssid=bssid or None), event, extra, **fields)

    def roamed(self, link: LinkInfo) -> EventLine:
        now = time.monotonic()
        old, self.last = self.last, link
        starts = [
            stamp for stamp in (self._auth_at, self._roam_cmd_at) if stamp is not None
        ]
        self._connect_at = now
        self._roam_origin = max(starts) if starts else None
        self._disc = None
        extra, fields = self.link_extra(link)
        old_mld = None
        if old.bssid:
            extra += f", old_bssid: ({old.bssid})"
            fields["old_bssid"] = old.bssid
            old_mld = _previous_mld(old)
        if old_mld:
            extra += f", old_ap_mld: ({old_mld})"
        fields["old_ap_mld"] = old_mld
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
        fresh = not by_ap and old.connected and bool(old.bssid)
        if fresh or by_ap:
            if fresh and old.bssid:
                self._disc = (time.monotonic(), old.bssid, bytes(old.ssid))
            else:
                self._disc = None
            self._connect_at = None
            self._roam_origin = None
            self._clear_auth()
        was_mlo = bool(old.extra.get("links")) or bool(old.extra.get("ap_mld"))
        kept: dict[str, Any] = {}
        if was_mlo and old.bssid:
            kept["ap_mld"] = old.bssid
        self.last = LinkInfo(bssid=old.bssid, extra=kept)
        gone = LinkInfo(bssid=old.bssid)
        extra = ""
        fields: dict[str, Any] = {}
        if was_mlo and old.bssid:
            fields["ap_mld"] = old.bssid
            fields["_mlo_address"] = True
        if reason is not None:
            extra += f", reason: ({reason} {reason_text(reason)})"
            fields.update(reason_code=reason, reason_text=reason_text(reason))
        extra += f", locally_generated: ({'no' if by_ap else 'yes'})"
        fields["locally_generated"] = not by_ap
        return self.line(gone, "disconnected", extra, **fields)

    def port_authorized(self, link: LinkInfo) -> EventLine:
        self.last = link
        now = time.monotonic()
        extra = ""
        fields: dict[str, Any] = {}
        if self._connect_at is not None:
            elapsed = _elapsed_ms(self._connect_at, now)
            extra += f", since_connect_ms: ({elapsed})"
            fields["since_connect_ms"] = elapsed
        if self._roam_origin is not None:
            total = _elapsed_ms(self._roam_origin, now)
            extra += f", roam_total_ms: ({total})"
            fields["roam_total_ms"] = total
        return self.line(link, "port_authorized", extra, **fields)

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
            assoc = link.extra.get("assoc_link_id")
            assoc_id = assoc if isinstance(assoc, int) else None
            if _association_id(updated, assoc_id) == link_id:
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
        gone = {item.get("id") for item in removed if item.get("id") is not None}
        source = link.extra.get("links")
        current = list(previous if source is None else source)
        link.extra["links"] = [item for item in current if item.get("id") not in gone]
        self.last = link
        return self.line(
            link,
            "link_removed",
            f", link: ({describe_links(described)})",
            affected=described,
        )

    def _scan_link(self) -> LinkInfo:
        if self.last.connected:
            return self.last
        return LinkInfo()

    def scan_started(self, frequencies: int | None) -> EventLine:
        extra = ""
        fields: dict[str, Any] = {}
        if frequencies is not None:
            extra = f", scan: ({frequencies} frequencies)"
            fields["scan_frequency_count"] = frequencies
        return self.line(self._scan_link(), "scan_started", extra, **fields)

    def scan_complete(self, count: int) -> EventLine:
        return self.line(
            self._scan_link(),
            "scan_complete",
            f", scan: ({count} BSSIDs found)",
            scan_bssid_count=count,
        )

    def scan_aborted(self) -> EventLine:
        return self.line(self._scan_link(), "scan_aborted")


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
        if cmd in (nl.CMD_AUTHENTICATE, nl.CMD_ASSOCIATE):
            formatter.observe_mlme(message.attrs)
            event = "auth_failed" if cmd == nl.CMD_AUTHENTICATE else "assoc_failed"
            if nl.ATTR_TIMED_OUT in message.attrs:
                bssid = nl.mac_str(message.attrs.get(nl.ATTR_MAC))
                return [formatter.mlme_failed(event, bssid, None, True)]
            frame = message.attrs.get(nl.ATTR_FRAME)
            rejected = auth_failure(frame) if frame else None
            if rejected:
                return [formatter.mlme_failed(event, *rejected, False)]
            return []
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
            return [formatter.connected(self._link(native), message.attrs)]
        if cmd == nl.CMD_ROAM:
            formatter.observe_roam(message.attrs)
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
        if cmd == nl.CMD_TRIGGER_SCAN:
            return [formatter.scan_started(scan_frequency_count(message.attrs))]
        if cmd == nl.CMD_SCAN_ABORTED:
            return [formatter.scan_aborted()]
        if cmd == nl.CMD_NEW_SCAN_RESULTS:
            try:
                count = len(self.backend.dump_scan(native))
            except (OSError, BackendError) as error:
                log.debug("%s: scan dump failed: %s", native.name, error)
                return []
            return [formatter.scan_complete(count)]
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
