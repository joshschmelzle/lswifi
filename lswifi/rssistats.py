#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause

"""
lswifi.rssistats
~~~~~~~~~~~~~~~~

Pure helpers for collecting and summarizing RSSI samples for --rssi-stats.
"""

import contextlib
import json
import os
import re
import statistics
import tempfile
from dataclasses import dataclass, field

from lswifi.helpers import (
    is_five_band,
    is_six_band,
    is_two_four_band,
    strip_mac_address_format,
)

RssiSamples = dict[tuple[str, str, str], list[tuple[str, int]]]


@dataclass(frozen=True)
class RssiLabel:
    ssid: str = ""
    ap_name: str = ""
    channel: str = ""
    channel_width: str = ""


RssiLabels = dict[tuple[str, str, str], RssiLabel]


@dataclass
class Freshness:
    scan_calls: int = 0
    fresh_scans: int = 0
    has_markers: bool = True
    fresh_times: list[float] = field(default_factory=list)
    started: float | None = None
    last_call: float | None = None
    previous: dict[tuple[str, str], int] = field(default_factory=dict)
    counted: dict[tuple[str, str], int] = field(default_factory=dict)

    def observe(self, markers: dict[tuple[str, str], int | None], now: float) -> bool:
        self.scan_calls += 1
        if self.started is None:
            self.started = now
        self.last_call = now
        if not markers:
            self.fresh_scans += 1
            self.fresh_times.append(now)
            return True
        if any(marker is None for marker in markers.values()):
            self.has_markers = False
            fresh = True
        else:
            known = {
                key: marker for key, marker in markers.items() if marker is not None
            }
            fresh = known != self.previous
            self.previous = known
        if fresh:
            self.fresh_scans += 1
            self.fresh_times.append(now)
        return fresh

    def is_fresh_reading(self, key: tuple[str, str], marker: int | None) -> bool:
        if marker is None or not self.has_markers:
            return True
        if self.counted.get(key) == marker:
            return False
        self.counted[key] = marker
        return True

    def gap_s(self) -> float | None:
        if len(self.fresh_times) < 2:
            return None
        return (self.fresh_times[-1] - self.fresh_times[0]) / (
            len(self.fresh_times) - 1
        )

    def duration_s(self) -> float:
        if self.started is None or self.last_call is None:
            return 0.0
        return self.last_call - self.started


@dataclass(frozen=True)
class RunInfo:
    scan_calls: int = 0
    duration_s: float = 0.0
    every_scan: bool = False


@dataclass(frozen=True)
class RssiSummary:
    interface_mac: str
    bssid: str
    band: str
    first_timestamp: str
    last_timestamp: str
    completed_scans: int
    samples: int
    mean_dbm: float
    stdev_db: float | None
    min_dbm: int
    max_dbm: int
    spread_db: int
    cv: float | None = None
    label: RssiLabel = RssiLabel()
    possibly_stale: bool = False
    run: RunInfo = RunInfo()


def band_of(frequency: str) -> str:
    if is_two_four_band(frequency):
        return "2.4 GHz"
    if is_five_band(frequency):
        return "5 GHz"
    if is_six_band(frequency):
        return "6 GHz"
    return ""


def is_full_bssid(text: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{12}", strip_mac_address_format(text)) is not None


def is_bssid_prefix(text: str) -> bool:
    return (
        is_full_bssid(text)
        or re.fullmatch(
            r"[0-9a-f]{2}(?:([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){0,4})?", text.lower()
        )
        is not None
    )


def matches_bssid(wanted: str, bssid: str) -> bool:
    want = strip_mac_address_format(wanted)
    have = strip_mac_address_format(bssid)
    return have == want if is_full_bssid(wanted) else have.startswith(want)


def add_sample(
    samples: RssiSamples,
    interface_mac: str,
    bssid: str,
    band: str,
    timestamp: str,
    rssi_dbm: object,
) -> None:
    if not isinstance(rssi_dbm, int):
        return
    samples.setdefault((interface_mac, bssid, band), []).append((timestamp, rssi_dbm))


def add_label(
    labels: RssiLabels,
    interface_mac: str,
    bssid: str,
    band: str,
    label: RssiLabel,
) -> None:
    key = (interface_mac, bssid, band)
    old = labels.get(key, RssiLabel())
    labels[key] = RssiLabel(
        ssid=label.ssid or old.ssid,
        ap_name=label.ap_name or old.ap_name,
        channel=label.channel or old.channel,
        channel_width=label.channel_width or old.channel_width,
    )


def cv_pct(values: list[int]) -> float | None:
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    if mean == 0:
        return None
    return round(100 * statistics.stdev(values) / abs(mean), 1)


def is_possibly_stale(values: list[int], completed_scans: int) -> bool:
    if len(values) < 2:
        return True
    return len(set(values)) == 1 and 2 * len(values) < completed_scans


def summarize(
    samples: RssiSamples,
    completed_scans: int | dict[str, int],
    labels: RssiLabels | None = None,
    runs: dict[str, RunInfo] | None = None,
) -> list[RssiSummary]:
    summaries = []
    for (interface_mac, bssid, band), entries in sorted(samples.items()):
        scans = (
            completed_scans.get(interface_mac, 0)
            if isinstance(completed_scans, dict)
            else completed_scans
        )
        values = [rssi for _timestamp, rssi in entries]
        min_dbm = min(values)
        max_dbm = max(values)
        summaries.append(
            RssiSummary(
                interface_mac=interface_mac,
                bssid=bssid,
                band=band,
                first_timestamp=entries[0][0],
                last_timestamp=entries[-1][0],
                completed_scans=scans,
                samples=len(values),
                mean_dbm=round(statistics.fmean(values), 1),
                stdev_db=(
                    round(statistics.stdev(values), 1) if len(values) >= 2 else None
                ),
                min_dbm=min_dbm,
                max_dbm=max_dbm,
                spread_db=max_dbm - min_dbm,
                cv=cv_pct(values),
                label=(labels or {}).get((interface_mac, bssid, band), RssiLabel()),
                possibly_stale=is_possibly_stale(values, scans),
                run=(runs or {}).get(interface_mac, RunInfo()),
            )
        )
    return summaries


def repeated_bssids(summaries: list[RssiSummary]) -> dict[tuple[str, str], list[str]]:
    bands: dict[tuple[str, str], list[str]] = {}
    for summary in summaries:
        bands.setdefault((summary.interface_mac, summary.bssid), []).append(
            summary.band
        )
    return {key: value for key, value in bands.items() if len(value) > 1}


def format_band_warning(
    interface_mac: str, bssid: str, bands: list[str], table: bool = False
) -> str:
    unit = "row" if table else "summary"
    return (
        f"{interface_mac} {bssid} was seen on {' and '.join(bands)}. "
        f"each band has its own {unit}. add -a, -g or -six to measure one band"
    )


def scan_noun(every_scan: bool) -> str:
    return "scan" if every_scan else "fresh scan"


def format_progress(
    index: int,
    total: int | None,
    readings: list[str],
    scan_calls: int,
    every_scan: bool = False,
) -> str:
    position = f"{index}/{total}" if total else f"{index}"
    text = (
        f"{scan_noun(every_scan)} {position}: "
        f"{', '.join(readings) if readings else 'not seen'}"
    )
    return text if every_scan else f"{text}  ({scan_calls} scan calls)"


def format_multi_progress(
    index: int,
    total: int | None,
    seen: int,
    matched: int,
    scan_calls: int,
    every_scan: bool = False,
) -> str:
    position = f"{index}/{total}" if total else f"{index}"
    text = f"{scan_noun(every_scan)} {position}  seen {seen}/{matched}"
    return text if every_scan else f"{text}  ({scan_calls} scan calls)"


def format_plan(
    matched: int, bands: int, scans: int | None, duration: int | None
) -> str:
    noun = "BSSID" if matched == 1 else "BSSIDs"
    band_noun = "band" if bands == 1 else "bands"
    run = f"{scans} fresh scans" if scans else f"fresh scans for {duration} s"
    return f"matched {matched} {noun} on {bands} {band_noun}; {run}, Ctrl-C to stop"


def format_estimate(gap_s: float, scans: int | None) -> str:
    text = f"the OS returns a fresh scan about every {gap_s:.0f} s"
    if scans:
        minutes = gap_s * scans / 60
        span = f"{minutes:.0f} min" if minutes >= 2 else f"{gap_s * scans:.0f} s"
        text += f"; {scans} fresh scans take about {span}"
    return text


EVERY_SCAN_NOTE = (
    "this OS does not say when each BSS was last heard, "
    "so every scan counts as a reading"
)


def format_run(run: RunInfo, fresh_scans: int) -> str:
    noun = "scans" if run.every_scan else "fresh scans"
    text = f"{fresh_scans} {noun}"
    if not run.every_scan:
        text += f" from {run.scan_calls} scan calls"
    return f"{text} over {run.duration_s:.0f} s"


def steadiness_key(summary: "RssiSummary") -> tuple[bool, float, float]:
    return (summary.possibly_stale, summary.stdev_db or 0.0, -summary.mean_dbm)


def format_table(summaries: list["RssiSummary"]) -> str:
    header = (
        "SSID",
        "AP name",
        "BSSID",
        "band",
        "ch",
        "samples",
        "mean",
        "stdev",
        "CV",
        "min",
        "max",
        "spread",
    )
    rows = [header]
    for summary in sorted(summaries, key=steadiness_key):
        rows.append(
            (
                summary.label.ssid or "-",
                summary.label.ap_name or "-",
                summary.bssid,
                summary.band or "-",
                summary.label.channel or "-",
                f"{summary.samples}/{summary.completed_scans}"
                + ("*" if summary.possibly_stale else ""),
                f"{summary.mean_dbm:.1f}",
                f"{summary.stdev_db:.1f}" if summary.stdev_db is not None else "-",
                f"{summary.cv:.1f}%" if summary.cv is not None else "-",
                str(summary.min_dbm),
                str(summary.max_dbm),
                str(summary.spread_db),
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = ["RSSI stats (steadiest first; dBm, stdev and spread in dB)"]
    lines.extend(
        "  ".join(
            cell.ljust(width) for cell, width in zip(row, widths, strict=True)
        ).rstrip()
        for row in rows
    )
    if any(summary.possibly_stale for summary in summaries):
        lines.append(
            "* possibly stale: heard in fewer than 2 fresh scans, or the same "
            "reading every time in fewer than half the fresh scans"
        )
    runs = {
        summary.interface_mac: format_run(summary.run, summary.completed_scans)
        for summary in summaries
    }
    for interface_mac in sorted(runs):
        lines.append(f"interface {interface_mac}: {runs[interface_mac]}")
    return "\n".join(lines)


def format_reading(band: str, rssi_dbm: int, show_band: bool) -> str:
    return f"{rssi_dbm} dBm ({band})" if show_band and band else f"{rssi_dbm} dBm"


def format_channel(summary: RssiSummary) -> str:
    parts = [summary.band]
    if summary.label.channel:
        parts.append(f"channel {summary.label.channel}")
    if summary.label.channel_width:
        parts.append(f"{summary.label.channel_width} MHz")
    return ", ".join(part for part in parts if part)


def format_summary(summary: RssiSummary) -> str:
    rows = [
        ("SSID", summary.label.ssid),
        ("AP name", summary.label.ap_name),
        ("BSSID", summary.bssid),
        ("band", format_channel(summary)),
        (
            "samples",
            f"{summary.samples} of {format_run(summary.run, summary.completed_scans)}",
        ),
        ("mean", f"{summary.mean_dbm:.1f} dBm"),
        (
            "stdev",
            f"{summary.stdev_db:.1f} dB" if summary.stdev_db is not None else "",
        ),
        (
            "CV",
            f"{summary.cv:.1f}%" if summary.cv is not None else "",
        ),
        ("min", f"{summary.min_dbm} dBm"),
        ("max", f"{summary.max_dbm} dBm"),
        ("spread", f"{summary.spread_db} dB"),
        ("interface", summary.interface_mac),
    ]
    lines = ["RSSI stats"]
    lines.extend(f"  {name:<10} {value}" for name, value in rows if value)
    return "\n".join(lines)


def as_number(text: str) -> int | str:
    return int(text) if text.isdigit() else text


def summary_to_json(
    summary: RssiSummary, bssid_bands: list[str] | None = None
) -> dict[str, str | int | float | list[str]]:
    result: dict[str, str | int | float | list[str]] = {
        "interface_mac": summary.interface_mac,
        "bssid": summary.bssid,
    }
    if summary.label.ssid:
        result["ssid"] = summary.label.ssid
    if summary.label.ap_name:
        result["ap_name"] = summary.label.ap_name
    if summary.band:
        result["band"] = summary.band
    if summary.label.channel:
        result["channel"] = as_number(summary.label.channel)
    if summary.label.channel_width:
        result["channel_width"] = as_number(summary.label.channel_width)
    if bssid_bands:
        result["bssid_bands"] = bssid_bands
    result |= {
        "first_timestamp": summary.first_timestamp,
        "last_timestamp": summary.last_timestamp,
        "completed_scans": summary.completed_scans,
        "samples": summary.samples,
        "mean_dbm": summary.mean_dbm,
    }
    if summary.stdev_db is not None:
        result["stdev_db"] = summary.stdev_db
    if summary.cv is not None:
        result["cv"] = summary.cv
    result["min_dbm"] = summary.min_dbm
    result["max_dbm"] = summary.max_dbm
    result["spread_db"] = summary.spread_db
    if summary.possibly_stale:
        result["possibly_stale"] = True
    if summary.run.scan_calls:
        result["scan_calls"] = summary.run.scan_calls
        result["duration_s"] = round(summary.run.duration_s, 1)
    if summary.run.every_scan:
        result["every_scan_counted"] = True
    return result


def append_to_json_file(
    path: str, summaries: list[RssiSummary], indent: int | None
) -> bool:
    if not os.path.exists(path):
        return False

    with open(path) as file:
        document = json.load(file)

    repeated = repeated_bssids(summaries)
    document.setdefault("rssi_stats", []).extend(
        summary_to_json(summary, repeated.get((summary.interface_mac, summary.bssid)))
        for summary in summaries
    )

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    file = os.fdopen(fd, "w")
    try:
        json.dump(document, file, indent=indent)
        file.close()
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            file.close()
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    return True
