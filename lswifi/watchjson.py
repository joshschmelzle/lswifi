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
lswifi.watchjson
~~~~~~~~~~~~~~~~

``--watchevents --json``: one JSON object per line (NDJSON) on stdout,
shared by the Windows, macOS, and Linux backends so all emit the same schema.

Every object has ``timestamp`` (ISO 8601, local offset, milliseconds, the
same style as the ``--json`` scan export), ``interface_mac`` and ``event``.
The common link fields follow when known: ``bssid``, ``freq_mhz``,
``ssid`` (``ssid_hex`` too when the SSID bytes are not valid UTF-8),
``rssi``. Event-specific keys come after them, for example ``channel``,
``width_mhz``, ``band``, ``noise``, ``tx_rate_mbps``, ``scan_bssid_count``,
``old_bssid``, ``old_freq_mhz``, ``old_rssi``, ``old_channel``,
``old_ssid``, ``reason_code``, ``reason_text``, ``ap_mld`` and ``*_ms``
join timing.

A value that is unknown or does not apply is omitted, never ``null`` or
``""``. Numbers are JSON numbers. Log messages stay on stderr; only these
objects go to stdout.
"""

import datetime
import json
import math
import sys
import threading
from typing import Any, TextIO

# key order of the common fields; event-specific keys follow
COMMON_KEYS = (
    "timestamp",
    "interface_mac",
    "event",
    "bssid",
    "freq_mhz",
    "ssid",
    "ssid_hex",
    "rssi",
)
ZERO_BSSID = "00:00:00:00:00:00"


def watch_json_requested(args) -> bool:
    """--watchevents together with --json"""
    return bool(getattr(args, "event_watcher", False) and getattr(args, "json", None))


def iso_timestamp(now: datetime.datetime | None = None) -> str:
    """2026-10-22T15:20:01.123-04:00"""
    now = now or datetime.datetime.now()
    return now.astimezone().isoformat(timespec="milliseconds")


def to_number(value: Any) -> int | float | None:
    """int or float from a number, a numeric string, or an object with .value"""
    if value is None or isinstance(value, bool):
        return None
    if hasattr(value, "value") and not isinstance(value, (int, float, str, bytes)):
        value = value.value
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):  # NaN/inf are not valid JSON
            return None
        return int(value) if value.is_integer() else value
    try:
        text = str(value).strip()
        if not text:
            return None
        number = float(text)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def freq_mhz(value: Any) -> int | None:
    """MHz from MHz or GHz ("5220", 5220, "5.220")"""
    number = to_number(value)
    if not number or number < 0:
        return None
    if number < 100:  # GHz, as Windows prints it after IE parsing
        number = number * 1000
    return int(round(number))


def ssid_fields(value: Any) -> dict:
    """{"ssid": str} and, for bytes that are not UTF-8, "ssid_hex" """
    if value is None:
        return {}
    if hasattr(value, "value") and not isinstance(value, (str, bytes, bytearray)):
        value = value.value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if not raw:
            return {}
        try:
            return {"ssid": raw.decode("utf-8")}
        except UnicodeDecodeError:
            return {
                "ssid": raw.decode("utf-8", errors="replace"),
                "ssid_hex": raw.hex(),
            }
    text = str(value)
    return {"ssid": text} if text else {}


def _bssid(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value") and not isinstance(value, str):
        value = value.value
    text = str(value).strip().lower()
    if not text or text == ZERO_BSSID:
        return None
    return text


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return value if value else None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return to_number(value)
    return value


def event_record(
    interface_mac: str,
    event: str,
    *,
    bssid: Any = None,
    freq: Any = None,
    ssid: Any = None,
    rssi: Any = None,
    **extra: Any,
) -> dict:
    """The schema both backends share; unknown values are dropped"""
    record: dict[str, Any] = {
        "interface_mac": str(interface_mac).lower(),
        "event": str(event).strip(),
    }
    if (b := _bssid(bssid)) is not None:
        record["bssid"] = b
    if (f := freq_mhz(freq)) is not None:
        record["freq_mhz"] = f
    record.update(ssid_fields(ssid))
    if (r := to_number(rssi)) is not None:
        record["rssi"] = r
    for key, value in extra.items():
        value = _clean(value)
        if value is not None:
            record[key] = value
    return record


def windows_event_record(
    mac: str,
    wlan_event: Any,
    bssid: Any = None,
    bss: Any = None,
    scan_count: int | None = None,
) -> dict:
    """Build the record from the values lswifi.client.on_event_notification has

    ``bss`` is the WirelessNetworkBss for the connected BSSID, when found.
    """
    fields: dict[str, Any] = {}
    if bss is not None:
        fields.update(
            freq=getattr(bss, "channel_frequency", None),
            ssid=getattr(bss, "ssid", None),
            rssi=getattr(bss, "rssi", None),
        )
        channel = to_number(getattr(bss, "channel_number", None))
        if channel:
            fields["channel"] = channel
    if scan_count is not None:
        fields["scan_bssid_count"] = int(scan_count)
    return event_record(mac, str(wlan_event), bssid=bssid, **fields)


def dumps(record: dict, timestamp: str | None = None) -> str:
    """One NDJSON line (no newline), timestamp first"""
    line = {
        "timestamp": timestamp or iso_timestamp(),
        **{k: v for k, v in record.items() if k != "timestamp"},
    }
    return json.dumps(line, separators=(", ", ": "), allow_nan=False)


class NDJSONWriter:
    """Thread-safe line writer; flushes every line"""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream
        self.lock = threading.Lock()
        self.closed = False

    def write(self, record: dict) -> None:
        line = dumps(record)
        with self.lock:
            if self.closed:
                return
            stream = self.stream or sys.stdout
            try:
                stream.write(line + "\n")
                stream.flush()
            except BrokenPipeError:  # e.g. `| head`; stop writing, keep running
                self.closed = True


_writer: NDJSONWriter | None = None


def shared_writer() -> NDJSONWriter:
    """One stdout writer per process, shared by every interface/thread"""
    global _writer
    if _writer is None:
        _writer = NDJSONWriter()
    return _writer


__all__ = [
    "NDJSONWriter",
    "dumps",
    "event_record",
    "freq_mhz",
    "iso_timestamp",
    "shared_writer",
    "ssid_fields",
    "to_number",
    "watch_json_requested",
    "windows_event_record",
]
