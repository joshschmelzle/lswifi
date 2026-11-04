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
from dataclasses import dataclass

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
    cv_power_pct: float | None = None
    label: RssiLabel = RssiLabel()


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


def power_cv_pct(values: list[int]) -> float | None:
    if len(values) < 2:
        return None
    milliwatts = [10 ** (value / 10) for value in values]
    return round(100 * statistics.stdev(milliwatts) / statistics.fmean(milliwatts), 1)


def summarize(
    samples: RssiSamples, completed_scans: int, labels: RssiLabels | None = None
) -> list[RssiSummary]:
    summaries = []
    for (interface_mac, bssid, band), entries in sorted(samples.items()):
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
                completed_scans=completed_scans,
                samples=len(values),
                mean_dbm=round(statistics.fmean(values), 1),
                stdev_db=(
                    round(statistics.stdev(values), 1) if len(values) >= 2 else None
                ),
                min_dbm=min_dbm,
                max_dbm=max_dbm,
                spread_db=max_dbm - min_dbm,
                cv_power_pct=power_cv_pct(values),
                label=(labels or {}).get((interface_mac, bssid, band), RssiLabel()),
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


def format_band_warning(interface_mac: str, bssid: str, bands: list[str]) -> str:
    return (
        f"{interface_mac} {bssid} was seen on {' and '.join(bands)}. "
        "each band has its own summary. add -a, -g or -six to measure one band"
    )


def format_progress(index: int, total: int | None, readings: list[str]) -> str:
    position = f"{index}/{total}" if total else f"{index}"
    return f"scan {position}: {', '.join(readings) if readings else 'not seen'}"


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
        ("samples", f"{summary.samples}/{summary.completed_scans} scans"),
        ("mean", f"{summary.mean_dbm:.1f} dBm"),
        (
            "stdev",
            f"{summary.stdev_db:.1f} dB" if summary.stdev_db is not None else "",
        ),
        (
            "CV",
            f"{summary.cv_power_pct:.1f}% of linear power (mW)"
            if summary.cv_power_pct is not None
            else "",
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
    if summary.cv_power_pct is not None:
        result["cv_power_pct"] = summary.cv_power_pct
    result["min_dbm"] = summary.min_dbm
    result["max_dbm"] = summary.max_dbm
    result["spread_db"] = summary.spread_db
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
