#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause

"""
lswifi.rssistats
~~~~~~~~~~~~~~~~

Pure helpers for collecting and summarizing RSSI samples matched by -bssid.
"""

import contextlib
import json
import os
import statistics
import tempfile
from dataclasses import dataclass

from lswifi.helpers import is_five_band, is_six_band, is_two_four_band

RssiSamples = dict[tuple[str, str, str], list[tuple[str, int]]]


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


def band_of(frequency: str) -> str:
    if is_two_four_band(frequency):
        return "2.4 GHz"
    if is_five_band(frequency):
        return "5 GHz"
    if is_six_band(frequency):
        return "6 GHz"
    return ""


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


def summarize(samples: RssiSamples, completed_scans: int) -> list[RssiSummary]:
    summaries = []
    for (interface_mac, bssid, band), entries in sorted(samples.items()):
        values = [rssi for _timestamp, rssi in entries]
        mean_dbm = round(statistics.fmean(values), 1)
        stdev_db = round(statistics.stdev(values), 1) if len(values) >= 2 else None
        min_dbm = min(values)
        max_dbm = max(values)
        spread_db = max_dbm - min_dbm
        summaries.append(
            RssiSummary(
                interface_mac=interface_mac,
                bssid=bssid,
                band=band,
                first_timestamp=entries[0][0],
                last_timestamp=entries[-1][0],
                completed_scans=completed_scans,
                samples=len(values),
                mean_dbm=mean_dbm,
                stdev_db=stdev_db,
                min_dbm=min_dbm,
                max_dbm=max_dbm,
                spread_db=spread_db,
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


def format_summary(summary: RssiSummary) -> str:
    band = f" {summary.band}" if summary.band else ""
    text = (
        f"{summary.interface_mac} {summary.bssid}{band}: "
        f"{summary.samples}/{summary.completed_scans} scans, "
        f"mean {summary.mean_dbm:.1f} dBm"
    )
    if summary.stdev_db is not None:
        text += f", stdev {summary.stdev_db:.1f} dB"
    text += (
        f", min {summary.min_dbm} dBm, max {summary.max_dbm} dBm, "
        f"spread {summary.spread_db} dB"
    )
    return text


def summary_to_json(
    summary: RssiSummary, bssid_bands: list[str] | None = None
) -> dict[str, str | int | float | list[str]]:
    result: dict[str, str | int | float | list[str]] = {
        "interface_mac": summary.interface_mac,
        "bssid": summary.bssid,
    }
    if summary.band:
        result["band"] = summary.band
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
