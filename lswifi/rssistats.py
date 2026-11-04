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


MISS_LIMIT = 10
IDLE_LIMIT = 60


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def clock(iso: str) -> str:
    return iso[11:19] if len(iso) >= 19 else iso


@dataclass
class Freshness:
    scan_calls: int = 0
    real_scans: int = 0
    samples: int = 0
    misses: int = 0
    miss_streak: int = 0
    idle_streak: int = 0
    has_markers: bool = True
    started: float | None = None
    last_sample: float | None = None
    sample_gap: float | None = None
    last_call: float | None = None
    started_at: str = ""
    ended_at: str = ""
    previous: dict[tuple[str, str], int] = field(default_factory=dict)
    counted: dict[tuple[str, str], int] = field(default_factory=dict)

    def observe(
        self,
        markers: dict[tuple[str, str], int | None],
        now: float,
        real: bool | None = None,
        at: str = "",
    ) -> bool:
        first = self.scan_calls == 0
        self.scan_calls += 1
        if self.started is None:
            self.started = now
            self.started_at = at
        self.last_call = now
        self.ended_at = at or self.ended_at
        if any(marker is None for marker in markers.values()):
            self.has_markers = False
        known = {key: marker for key, marker in markers.items() if marker is not None}
        changed = known != self.previous
        self.previous = known
        if real is not None:
            is_real = real
        elif not markers or not self.has_markers:
            is_real = True
        elif first:
            self.counted = dict(known)
            is_real = False
        else:
            is_real = changed
        self.idle_streak = 0 if is_real else self.idle_streak + 1
        if is_real:
            self.real_scans += 1
        return is_real

    def is_fresh_reading(self, key: tuple[str, str], marker: int | None) -> bool:
        if marker is None or not self.has_markers:
            return True
        if self.counted.get(key) == marker:
            return False
        self.counted[key] = marker
        return True

    def record(self, measured: bool) -> None:
        if measured:
            now = self.last_call
            self.sample_gap = (
                now - self.last_sample
                if now is not None and self.last_sample is not None
                else None
            )
            self.last_sample = now
            self.samples += 1
            self.miss_streak = 0
        else:
            self.misses += 1
            self.miss_streak += 1

    def duration_s(self) -> float:
        if self.started is None or self.last_call is None:
            return 0.0
        return self.last_call - self.started


@dataclass(frozen=True)
class RunInfo:
    scan_calls: int = 0
    duration_s: float = 0.0
    every_scan: bool = False
    started_at: str = ""
    ended_at: str = ""


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
    readings: tuple[tuple[str, int], ...] = ()


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
                readings=tuple(entries),
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


def format_progress(
    at: str,
    index: int,
    total: int | None,
    readings: list[str],
    gap_s: float | None = None,
) -> str:
    position = f"{index}/{total}" if total else f"{index}"
    text = f"{clock(at)} sample {position}: {', '.join(readings)}"
    if gap_s is not None:
        text += f" (+{gap_s:.0f} s)"
    return text


def format_miss(at: str, misses: int) -> str:
    return f"{clock(at)} not heard in this scan ({misses} missed so far)"


def format_multi_progress(
    at: str, index: int, total: int | None, seen: int, matched: int
) -> str:
    position = f"{index}/{total}" if total else f"{index}"
    return f"{clock(at)} scan {position}  seen {seen}/{matched}"


def format_plan(
    matched: int, bands: int, scans: int | None, duration: int | None
) -> str:
    noun = "BSSID" if matched == 1 else "BSSIDs"
    band_noun = "band" if bands == 1 else "bands"
    run = plural(scans, "scan") if scans else f"scans for {duration} s"
    return f"matched {matched} {noun} on {bands} {band_noun}; {run}, Ctrl-C to stop"


EVERY_SCAN_NOTE = (
    "this OS does not say when each BSS was last heard, "
    "so every scan counts as a reading"
)


def format_span(run: RunInfo) -> str:
    text = f"{run.duration_s:.0f} s"
    if run.started_at and run.ended_at:
        text = f"{clock(run.started_at)} to {clock(run.ended_at)} ({text})"
    return text


def format_samples(summary: "RssiSummary") -> str:
    missed = summary.completed_scans - summary.samples
    text = f"{summary.samples} of {plural(summary.completed_scans, 'scan')}"
    if missed > 0:
        text += f", {missed} missed"
    return text


def format_measuring(scans: int | None, duration: int | None) -> str:
    run = plural(scans, "sample") if scans else f"for {duration} s"
    return f"measuring {run}, Ctrl-C to stop"


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
            "* possibly stale: heard in fewer than 2 scans, or the same "
            "reading every time in fewer than half the scans"
        )
    runs = {
        summary.interface_mac: (
            f"{plural(summary.completed_scans, 'scan')}, {format_span(summary.run)}"
        )
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


def format_rows(rows: list[tuple[str, str]]) -> list[str]:
    return [f"  {name:<10} {value}" for name, value in rows if value]


def format_target(interface_mac: str, bssid: str, band: str, label: RssiLabel) -> str:
    probe = RssiSummary(
        interface_mac, bssid, band, "", "", 0, 0, 0.0, None, 0, 0, 0, label=label
    )
    rows = [
        ("SSID", label.ssid),
        ("AP name", label.ap_name),
        ("BSSID", bssid),
        ("band", format_channel(probe)),
        ("interface", interface_mac),
    ]
    return "\n".join(["target", *format_rows(rows)])


def format_summary(summary: RssiSummary) -> str:
    rows = [
        ("BSSID", summary.bssid),
        ("band", format_channel(summary)),
        ("samples", format_samples(summary)),
        ("time", format_span(summary.run)),
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
    ]
    return "\n".join(["RSSI stats", *format_rows(rows)])


def as_number(text: str) -> int | str:
    return int(text) if text.isdigit() else text


def summary_to_json(
    summary: RssiSummary, bssid_bands: list[str] | None = None
) -> dict[str, object]:
    result: dict[str, object] = {
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
    if summary.completed_scans > summary.samples:
        result["missed"] = summary.completed_scans - summary.samples
    if summary.run.started_at:
        result["started"] = summary.run.started_at
    if summary.run.ended_at:
        result["ended"] = summary.run.ended_at
    if summary.readings:
        result["readings"] = [
            {"timestamp": timestamp, "rssi_dbm": rssi}
            for timestamp, rssi in summary.readings
        ]
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
