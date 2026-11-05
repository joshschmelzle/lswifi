import json
import logging
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from lswifi import __main__ as lswifi_main
from lswifi import app, rssistats
from lswifi.backends import macos, macos_location
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from tests.test_backends import FakeBackend, Session, parse

IFACE_MAC = "00:00:5e:00:53:aa"
BSSID_A = "00:00:5e:00:53:01"
BSSID_B = "00:00:5e:00:53:02"
SSID = b"ExampleNet"


def record(
    rssi_dbm,
    bssid=BSSID_A,
    connected=False,
    frequency_mhz=5180,
    last_seen=None,
    ssid=SSID,
):
    return BssRecord(
        ssid=ssid,
        bssid=bssid,
        frequency_mhz=frequency_mhz,
        rssi_dbm=rssi_dbm,
        connected=connected,
        last_seen=last_seen,
    )


class SequenceBackend(FakeBackend):
    def __init__(self, scans):
        super().__init__([])
        self.iface.mac = IFACE_MAC
        self.scans = scans
        self.calls = 0

    def scan(self, iface):
        result = list(self.scans[self.calls])
        self.calls += 1
        return result


def block_rows(text, title):
    block = text[text.index(title) :].split("\n\n")[0]
    rows = {}
    for line in block.splitlines()[1:]:
        if not line.startswith("  "):
            break
        name, _, value = line.strip().partition("  ")
        rows.setdefault(name, value.strip())
    return rows


def summary_rows(text):
    rows = block_rows(text, "target\n") if "target\n" in text else {}
    return rows | block_rows(text, "RSSI stats")


def progress(text):
    return [
        re.sub(r" \(\+\d+ s\)$", "", line[9:])
        for line in text.splitlines()
        if re.match(r"\d\d:\d\d:\d\d ", line)
    ]


def table_rows(text):
    lines = text[text.index("RSSI stats\nSSID ") :].splitlines()[1:]
    header = lines[0]
    names = [
        "SSID",
        "AP name",
        "BSSID",
        "band",
        "ch",
        "samples",
        "mean",
        "stdev",
        "range",
    ]
    headings = [*names[:6], "mean dBm", "stdev dB", "range dB"]
    starts = [header.index(name) for name in headings]
    rows = []
    for line in lines[1:]:
        if line.startswith(("  ", "* ")):
            break
        cells = [
            line[a:b].strip() for a, b in zip(starts, [*starts[1:], None], strict=True)
        ]
        rows.append(dict(zip(names, cells, strict=True)))
    return rows


def fake_clock(monkeypatch, step):
    ticks = iter(range(0, 10_000 * step, step))
    monkeypatch.setattr(app.time, "perf_counter", lambda: next(ticks))
    monkeypatch.setattr(app.time, "sleep", lambda _seconds: None)


def stats_args(*extra):
    return parse(["-bssid", BSSID_A, "-all", "--rssi-stats", "-i", "0", *extra])


class TestRssiStatsUnit:
    def test_summarize_three_samples(self):
        samples = {
            (IFACE_MAC, BSSID_A, "5 GHz"): [
                ("2026-01-01T00:00:00", -60),
                ("2026-01-01T00:00:01", -62),
                ("2026-01-01T00:00:02", -64),
            ]
        }
        summaries = rssistats.summarize(samples, 3)
        assert len(summaries) == 1
        s = summaries[0]
        assert s.samples == 3
        assert s.mean_dbm == -62.0
        assert s.stdev_db == 2.0
        assert s.min_dbm == -64
        assert s.max_dbm == -60
        assert s.spread_db == 4
        assert s.first_timestamp == "2026-01-01T00:00:00"
        assert s.last_timestamp == "2026-01-01T00:00:02"

    def test_summarize_one_sample_has_no_stdev(self):
        samples = {(IFACE_MAC, BSSID_A, "5 GHz"): [("2026-01-01T00:00:00", -60)]}
        summaries = rssistats.summarize(samples, 1)
        assert summaries[0].samples == 1
        assert summaries[0].mean_dbm == -60.0
        assert summaries[0].stdev_db is None
        assert summaries[0].min_dbm == -60
        assert summaries[0].max_dbm == -60
        assert summaries[0].spread_db == 0
        assert "stdev_db" not in rssistats.summary_to_json(summaries[0])
        assert "min_dbm" in rssistats.summary_to_json(summaries[0])
        assert "max_dbm" in rssistats.summary_to_json(summaries[0])
        assert "spread_db" in rssistats.summary_to_json(summaries[0])
        assert "cv" not in rssistats.summary_to_json(summaries[0])
        assert "stdev" not in rssistats.format_summary(summaries[0])
        assert "CV" not in rssistats.format_summary(summaries[0])

    def test_summarize_sorts_by_interface_mac_then_bssid(self):
        samples = {
            ("00:00:5e:00:53:bb", BSSID_A, "5 GHz"): [("t1", -60)],
            (IFACE_MAC, BSSID_B, "5 GHz"): [("t2", -62)],
            (IFACE_MAC, BSSID_A, "5 GHz"): [("t3", -64)],
        }
        summaries = rssistats.summarize(samples, 1)
        assert [(s.interface_mac, s.bssid) for s in summaries] == [
            (IFACE_MAC, BSSID_A),
            (IFACE_MAC, BSSID_B),
            ("00:00:5e:00:53:bb", BSSID_A),
        ]

    @pytest.mark.parametrize(
        "text",
        [BSSID_A, BSSID_A.upper(), BSSID_A.replace(":", "-"), "00005e005301"],
    )
    def test_full_bssid_forms_are_accepted(self, text):
        assert rssistats.is_full_bssid(text)

    @pytest.mark.parametrize(
        "text", ["00:00:5e", "00:00:5e:00:53", "00:00:5e:00:53:0g"]
    )
    def test_partial_bssid_is_not_full(self, text):
        assert not rssistats.is_full_bssid(text)

    def test_add_sample_with_none_rssi_is_ignored(self):
        samples = {}
        rssistats.add_sample(samples, IFACE_MAC, BSSID_A, "5 GHz", "t1", None)
        assert samples == {}

    def test_summary_to_json_key_set_and_types(self):
        summary = rssistats.RssiSummary(
            interface_mac=IFACE_MAC,
            bssid=BSSID_A,
            band="5 GHz",
            first_timestamp="2026-01-01T00:00:00",
            last_timestamp="2026-01-01T00:00:01",
            completed_scans=2,
            samples=2,
            mean_dbm=-61.0,
            stdev_db=1.0,
            min_dbm=-62,
            max_dbm=-60,
            spread_db=2,
            label=rssistats.RssiLabel(
                ssid="ExampleNet", ap_name="AP-12", channel="36", channel_width="20"
            ),
        )
        obj = rssistats.summary_to_json(summary)
        assert set(obj) == {
            "interface_mac",
            "bssid",
            "ssid",
            "ap_name",
            "band",
            "channel",
            "channel_width",
            "first_timestamp",
            "last_timestamp",
            "completed_scans",
            "samples",
            "mean_dbm",
            "stdev_db",
            "min_dbm",
            "max_dbm",
            "spread_db",
        }
        assert None not in obj.values()
        assert (obj["channel"], obj["channel_width"]) == (36, 20)
        assert "cv" not in obj
        assert isinstance(obj["interface_mac"], str)
        assert isinstance(obj["bssid"], str)
        assert obj["band"] == "5 GHz"
        assert isinstance(obj["first_timestamp"], str)
        assert isinstance(obj["last_timestamp"], str)
        assert isinstance(obj["completed_scans"], int)
        assert isinstance(obj["samples"], int)
        assert isinstance(obj["mean_dbm"], float)
        assert isinstance(obj["stdev_db"], float)
        assert isinstance(obj["min_dbm"], int)
        assert isinstance(obj["max_dbm"], int)
        assert isinstance(obj["spread_db"], int)

    def test_append_to_json_file_missing_path_returns_false(self, tmp_path):
        path = tmp_path / "missing.json"
        summary = rssistats.RssiSummary(
            IFACE_MAC, BSSID_A, "5 GHz", "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
        )
        assert rssistats.append_to_json_file(str(path), [summary], 4) is False
        assert not path.exists()

    def test_append_to_json_file_keeps_existing_data_and_appends(self, tmp_path):
        path = tmp_path / "out.json"
        existing = {
            "lswifi": {"version": "lswifi 0.5.0"},
            "scan_data": [{"bssid": BSSID_A}],
            "rssi_stats": [{"bssid": BSSID_A, "samples": 1}],
        }
        path.write_text(json.dumps(existing))
        summary = rssistats.RssiSummary(
            IFACE_MAC, BSSID_A, "5 GHz", "t1", "t2", 2, 2, -61.0, 1.0, -62, -60, 2
        )
        assert rssistats.append_to_json_file(str(path), [summary], 4) is True
        document = json.loads(path.read_text())
        assert document["lswifi"] == existing["lswifi"]
        assert document["scan_data"] == existing["scan_data"]
        assert len(document["rssi_stats"]) == 2
        assert document["rssi_stats"][1]["samples"] == 2

    def test_append_to_json_file_atomic_on_oserror(self, tmp_path, monkeypatch):
        path = tmp_path / "out.json"
        original = {"lswifi": {"version": "lswifi 0.5.0"}, "scan_data": []}
        path.write_text(json.dumps(original))
        summary = rssistats.RssiSummary(
            IFACE_MAC, BSSID_A, "5 GHz", "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
        )

        real_dump = json.dump

        def failing_dump(*args, **kwargs):
            real_dump(*args, **kwargs)
            raise OSError("disk full")

        monkeypatch.setattr(json, "dump", failing_dump)
        with pytest.raises(OSError, match="disk full"):
            rssistats.append_to_json_file(str(path), [summary], 4)

        assert json.loads(path.read_text()) == original
        assert len(list(tmp_path.iterdir())) == 1

    def test_append_to_json_file_atomic_on_keyboard_interrupt(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "out.json"
        original = {"lswifi": {"version": "lswifi 0.5.0"}, "scan_data": []}
        path.write_text(json.dumps(original))
        summary = rssistats.RssiSummary(
            IFACE_MAC, BSSID_A, "5 GHz", "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
        )

        real_dump = json.dump

        def failing_dump(*args, **kwargs):
            real_dump(*args, **kwargs)
            raise KeyboardInterrupt

        monkeypatch.setattr(json, "dump", failing_dump)
        with pytest.raises(KeyboardInterrupt):
            rssistats.append_to_json_file(str(path), [summary], 4)

        assert json.loads(path.read_text()) == original
        assert len(list(tmp_path.iterdir())) == 1


class TestParseBssListSampling:
    def _session(self, records):
        data = [WirelessNetworkBss(r) for r in records]
        session = Session(data)
        session.mac = IFACE_MAC
        return session

    def test_connected_record_stored_without_marker(self):
        scanner = app.lswifi()
        args = stats_args()
        session = self._session([record(-60, connected=True)])
        scanner.parse_bss_list(session, False, "", "", args)
        assert (IFACE_MAC, BSSID_A, "5 GHz") in scanner.rssi_samples
        assert (IFACE_MAC, f"{BSSID_A}(*)", "5 GHz") not in scanner.rssi_samples

    def test_none_rssi_not_stored(self):
        scanner = app.lswifi()
        args = stats_args()
        session = self._session([record(None)])
        scanner.parse_bss_list(session, False, "", "", args)
        assert scanner.rssi_samples == {}

    def test_without_rssi_stats_store_stays_empty(self):
        scanner = app.lswifi()
        args = parse(["-bssid", BSSID_A, "-all"])
        session = self._session([record(-60)])
        scanner.parse_bss_list(session, False, "", "", args)
        assert scanner.rssi_samples == {}

    def test_bssid_matches_exactly_and_ignores_case(self):
        scanner = app.lswifi()
        args = parse(["-bssid", BSSID_A.upper(), "-all", "--rssi-stats"])
        records = [record(-60, bssid=BSSID_A), record(-62, bssid="00:00:5e:00:53:011")]
        scanner.parse_bss_list(self._session(records), False, "", "", args)
        assert set(scanner.rssi_samples) == {(IFACE_MAC, BSSID_A, "5 GHz")}

    def test_label_keeps_channel_and_width(self):
        scanner = app.lswifi()
        session = self._session([record(-60, connected=True)])
        scanner.parse_bss_list(session, False, "", "", stats_args())
        label = scanner.rssi_labels[(IFACE_MAC, BSSID_A, "5 GHz")]
        assert (label.ssid, label.channel, label.channel_width) == (
            "ExampleNet",
            "36",
            "20",
        )


def run_main(monkeypatch, backend, argv):
    monkeypatch.setattr(lswifi_main, "get_backend", lambda: backend)
    monkeypatch.setattr(sys, "argv", ["lswifi", *argv])
    with pytest.raises(SystemExit) as exited:
        lswifi_main.main()
    return exited.value.code


class TestCliValidation:
    def test_rssi_stats_without_bssid_measures_connected(self, monkeypatch, capsys):
        backend = SequenceBackend(
            [[record(-60, connected=True), record(-50, bssid=BSSID_B)]]
        )
        code = run_main(monkeypatch, backend, ["--rssi-stats", "-n", "1", "-i", "0"])
        assert code == 0
        out = capsys.readouterr().out
        rows = summary_rows(out)
        assert (rows["SSID"], rows["BSSID"], rows["samples"]) == (
            "ExampleNet",
            BSSID_A,
            "1 of 1 scan",
        )
        assert BSSID_B not in out

    def test_rssi_stats_without_all_keeps_weak_readings(self, monkeypatch, capsys):
        backend = SequenceBackend([[record(-60)], [record(-90)]])
        argv = ["-bssid", BSSID_A, "--rssi-stats", "-n", "2", "-i", "0"]
        assert run_main(monkeypatch, backend, argv) == 0
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["samples"], rows["mean"]) == ("2 of 2 scans", "-75.0 dBm")

    def test_defaults_to_30_scans_two_seconds_apart(self, monkeypatch, capsys):
        sleeps = []
        monkeypatch.setattr(app.time, "sleep", sleeps.append)
        backend = SequenceBackend([[record(-60, connected=True)]] * 30)
        assert run_main(monkeypatch, backend, ["--rssi-stats"]) == 0
        assert backend.calls == 30
        assert sleeps.count(2) == 29
        assert summary_rows(capsys.readouterr().out)["samples"] == "30 of 30 scans"

    def test_explicit_scans_and_interval_override_the_defaults(
        self, monkeypatch, capsys
    ):
        sleeps = []
        monkeypatch.setattr(app.time, "sleep", sleeps.append)
        backend = SequenceBackend([[record(-60, connected=True)]] * 3)
        argv = ["--rssi-stats", "-n", "3", "-i", "5"]
        assert run_main(monkeypatch, backend, argv) == 0
        assert backend.calls == 3
        assert sleeps.count(5) == 2
        assert 2 not in sleeps

    @pytest.mark.parametrize(
        "value",
        [
            "00:00:5",
            "00:00:5e:",
            "00:0g:5e",
            "00:00-5e",
            "0:0:5e",
            "00:00:5e:00:53:01:02",
        ],
    )
    def test_malformed_prefix_is_rejected(self, monkeypatch, capsys, value):
        backend = SequenceBackend([[record(-60)]])
        argv = ["--rssi-stats", "-bssid", value]
        assert run_main(monkeypatch, backend, argv) == 2
        assert "--rssi-stats needs a BSSID or a prefix" in capsys.readouterr().err
        assert backend.calls == 0

    @pytest.mark.parametrize("value", ["00:00:5e", "00-00-5E", "00", "00:00:5e:00:53"])
    def test_prefix_is_accepted(self, monkeypatch, value):
        backend = SequenceBackend([[record(-60)]])
        argv = ["--rssi-stats", "-bssid", value, "-n", "1", "-i", "0"]
        assert run_main(monkeypatch, backend, argv) == 0

    @pytest.mark.parametrize("flag", ["-threshold", "-t"])
    @pytest.mark.parametrize("value", ["-82", "-70"])
    def test_threshold_with_rssi_stats_is_rejected(
        self, monkeypatch, capsys, flag, value
    ):
        backend = SequenceBackend([[record(-60)]])
        argv = ["-bssid", BSSID_A, "--rssi-stats", flag, value]
        assert run_main(monkeypatch, backend, argv) == 2
        assert "-threshold (-t) is incompatible with --rssi-stats" in (
            capsys.readouterr().err
        )
        assert backend.calls == 0

    def test_all_is_accepted_and_left_out_of_help(self, monkeypatch, capsys):
        backend = SequenceBackend([[record(-60, connected=True)]])
        argv = ["--rssi-stats", "-all", "-n", "1", "-i", "0"]
        assert run_main(monkeypatch, backend, argv) == 0
        help_text = lswifi_main.appsetup.setup_parser().format_help()
        rssi_help = help_text[help_text.index("--rssi-stats  ") :].split("--ap-names")[
            0
        ]
        assert "-all" not in rssi_help


class TestConnectedTarget:
    def test_summarizes_only_the_connected_bssid(self, tmp_path, capsys):
        scans = [
            [record(-60, connected=True), record(-50, bssid=BSSID_B)],
            [record(-64, connected=True), record(-52, bssid=BSSID_B)],
        ]
        path = tmp_path / "out.json"
        args = parse(["--rssi-stats", "-i", "0", "-n", "2", "--json", str(path)])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=SequenceBackend(scans))
        assert exited.value.code == 0
        out = capsys.readouterr().out
        rows = summary_rows(out)
        assert (rows["BSSID"], rows["band"], rows["mean"]) == (
            BSSID_A,
            "5 GHz, channel 36, 20 MHz",
            "-62.0 dBm",
        )
        assert BSSID_B not in out
        document = json.loads(path.read_text())
        assert [(e["bssid"], e["ssid"]) for e in document["rssi_stats"]] == [
            (BSSID_A, "ExampleNet")
        ]
        assert {row["bssid"] for row in document["scan_data"]} == {BSSID_A}

    def test_progress_replaces_the_table(self, capsys, monkeypatch):
        fake_clock(monkeypatch, 3)
        scans = [
            [record(-60, connected=True)],
            [],
            [record(-64, connected=True)],
            [record(-66, connected=True)],
        ]
        args = parse(["--rssi-stats", "-i", "0", "-n", "3"])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        out = capsys.readouterr().out
        assert progress(out)[:3] == [
            "sample 1/3: -60 dBm",
            "not heard in this scan (1 missed so far)",
            "sample 2/3: -64 dBm",
        ]
        assert "AMENDMENTS" not in out

    def test_summary_lists_every_field_with_interface_last(self, capsys):
        scans = [[record(v, connected=True)] for v in (-60, -62, -64)]
        args = parse(["--rssi-stats", "-i", "0", "-n", "3"])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        rows = summary_rows(capsys.readouterr().out)
        assert list(rows) == [
            "SSID",
            "BSSID",
            "band",
            "interface",
            "samples",
            "time",
            "interval",
            "mean",
            "stdev",
            "range",
        ]
        assert rows["stdev"] == "2.0 dB (sample, n-1)"
        assert "CV" not in rows
        assert rows["range"] == "4 dB (min -64, max -60 dBm)"
        assert rows["interface"] == f"Wi-Fi ({IFACE_MAC})"

    def test_band_flag_that_excludes_the_link_exits_2_after_one_scan(
        self, capsys, caplog
    ):
        backend = SequenceBackend([[record(-60, connected=True)]] * 3)
        args = parse(["--rssi-stats", "-i", "0", "-n", "3", "-six"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 2
        assert backend.calls == 1
        assert (
            f"the connected BSSID on {IFACE_MAC} is on 5 GHz, which -six leaves out"
            in caplog.text
        )
        assert "RSSI stats" not in capsys.readouterr().out

    def test_band_flag_that_keeps_the_link_measures_it(self, capsys):
        backend = SequenceBackend([[record(-60, connected=True)]])
        args = parse(["--rssi-stats", "-i", "0", "-n", "1", "-a"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 0
        assert summary_rows(capsys.readouterr().out)["BSSID"] == BSSID_A

    def test_not_connected_exits_before_scanning(self, caplog):
        backend = SequenceBackend([[record(-60)]])
        backend.iface.state_string = "disconnected"
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["--rssi-stats", "-i", "0"]), backend=backend)
        assert exited.value.code == 2
        assert "no Wi-Fi interface is connected" in caplog.text
        assert backend.calls == 0

    def test_explicit_bssid_works_when_not_connected(self, capsys):
        backend = SequenceBackend([[record(-60)]])
        backend.iface.state_string = "disconnected"
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "1"), backend=backend)
        assert exited.value.code == 0
        assert summary_rows(capsys.readouterr().out)["samples"] == "1 of 1 scan"

    def test_ethers_name_labels_the_summary_and_json(
        self, tmp_path, capsys, monkeypatch
    ):
        monkeypatch.setattr(app.lswifi, "loadEthers", lambda self: {BSSID_A: "AP-12"})
        path = tmp_path / "out.json"
        args = parse(["--rssi-stats", "-ethers", "-i", "0", "--json", str(path)])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend([[record(-60, connected=True)]]))
        assert summary_rows(capsys.readouterr().out)["AP name"] == "AP-12"
        stats = json.loads(path.read_text())["rssi_stats"][0]
        assert (stats["ssid"], stats["ap_name"]) == ("ExampleNet", "AP-12")
        assert (stats["channel"], stats["channel_width"]) == (36, 20)

    def test_hidden_ssid_and_no_name_leave_labels_out(self, tmp_path, capsys):
        hidden = BssRecord(
            ssid=b"", bssid=BSSID_A, frequency_mhz=5180, rssi_dbm=-60, connected=True
        )
        path = tmp_path / "out.json"
        args = parse(["--rssi-stats", "-i", "0", "--json", str(path)])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend([[hidden]]))
        rows = summary_rows(capsys.readouterr().out)
        assert "SSID" not in rows
        assert "AP name" not in rows
        stats = json.loads(path.read_text())["rssi_stats"][0]
        assert "ssid" not in stats
        assert "ap_name" not in stats
        assert None not in stats.values()


class TestAppRun:
    def test_three_scans_json_summary_and_keys(self, tmp_path, capsys):
        backend = SequenceBackend([[record(-60)], [record(-62)], [record(-64)]])
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("--json", str(path), "-n", "3"),
                backend=backend,
            )
        assert exited.value.code == 0
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["samples"], rows["mean"], rows["stdev"]) == (
            "3 of 3 scans",
            "-62.0 dBm",
            "2.0 dB (sample, n-1)",
        )

        document = json.loads(path.read_text())
        assert len(document["rssi_stats"]) == 1
        stats = document["rssi_stats"][0]
        assert set(stats) == {
            "interface_mac",
            "bssid",
            "ssid",
            "band",
            "channel",
            "channel_width",
            "first_timestamp",
            "last_timestamp",
            "completed_scans",
            "samples",
            "mean_dbm",
            "stdev_db",
            "min_dbm",
            "max_dbm",
            "spread_db",
            "scan_calls",
            "duration_s",
            "started",
            "ended",
            "interval_s",
            "readings",
            "every_scan_counted",
        }
        assert isinstance(stats["min_dbm"], int)
        assert isinstance(stats["max_dbm"], int)
        assert isinstance(stats["spread_db"], int)
        assert "cv" not in stats
        timestamps = [row["timestamp"] for row in document["scan_data"]]
        assert stats["first_timestamp"] == timestamps[0]
        assert stats["last_timestamp"] == timestamps[-1]

    def test_bssid_on_two_bands_gets_one_summary_per_band_and_a_warning(
        self, tmp_path, capsys, caplog
    ):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend(
            [
                [record(-40, frequency_mhz=2412), record(-60)],
                [record(-42, frequency_mhz=2412), record(-64)],
            ]
        )
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit):
            app.run(stats_args("--json", str(path), "-n", "2"), backend=backend)

        out = capsys.readouterr().out
        assert "sample 1/2: -40 dBm (2.4 GHz), -60 dBm (5 GHz)" in progress(out)
        blocks = out[out.index("RSSI stats") :].split("\n\n")
        assert [summary_rows(block)["mean"] for block in blocks] == [
            "-41.0 dBm",
            "-62.0 dBm",
        ]
        band_warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.WARNING and "was seen on" in r.getMessage()
        ]
        assert band_warnings == [
            f"{IFACE_MAC} {BSSID_A} was seen on 2.4 GHz and 5 GHz. each band has "
            "its own summary. add -a, -g or -six to measure one band"
        ]
        stats = json.loads(path.read_text())["rssi_stats"]
        assert [(e["bssid"], e["band"], e["mean_dbm"]) for e in stats] == [
            (BSSID_A, "2.4 GHz", -41.0),
            (BSSID_A, "5 GHz", -62.0),
        ]
        assert [e["bssid_bands"] for e in stats] == [["2.4 GHz", "5 GHz"]] * 2

    def test_two_runs_into_one_file_append(self, tmp_path):
        path = tmp_path / "out.json"
        for _ in range(2):
            backend = SequenceBackend([[record(-60)], [record(-62)], [record(-64)]])
            with pytest.raises(SystemExit):
                app.run(
                    stats_args("--json", str(path), "-n", "3"),
                    backend=backend,
                )
        document = json.loads(path.read_text())
        assert len(document["rssi_stats"]) == 2
        assert len(document["scan_data"]) == 6

    def test_missed_scan_does_not_use_up_a_sample(self, capsys):
        backend = SequenceBackend([[record(-60)], [], [record(-64)], [record(-62)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "3", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        assert backend.calls == 4
        assert (
            summary_rows(capsys.readouterr().out)["samples"] == "3 of 4 scans, 1 missed"
        )

    def test_weak_rssi_below_default_threshold_counts(self, capsys):
        backend = SequenceBackend([[record(-60)], [record(-90)], [record(-62)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "3", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        assert summary_rows(capsys.readouterr().out)["samples"] == "3 of 3 scans"

    def test_one_scan_no_stdev(self, capsys):
        backend = SequenceBackend([[record(-60)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "1", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["mean"], rows["range"]) == (
            "-60.0 dBm",
            "0 dB (min -60, max -60 dBm)",
        )
        assert "stdev" not in rows
        assert "CV" not in rows

    def test_no_match_exits_2_and_creates_no_json(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[]] * rssistats.MISS_LIMIT)
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("--json", str(path), "-n", "1", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 2
        assert (
            f"no samples matched -bssid {BSSID_A} in {rssistats.MISS_LIMIT} scans"
            in caplog.text
        )
        assert not path.exists()

    def test_without_rssi_stats_no_summary_or_key(self, tmp_path, capsys):
        backend = SequenceBackend([[record(-60)]])
        path = tmp_path / "out.json"
        args = parse(["-bssid", BSSID_A, "-all", "--json", str(path), "-n", "1"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 0
        assert "RSSI stats" not in capsys.readouterr().out
        assert "rssi_stats" not in json.loads(path.read_text())


@pytest.mark.skipif(sys.platform == "win32", reason="sends SIGINT")
def test_ctrl_c_prints_summary_without_json_write(tmp_path):
    path = tmp_path / "out.json"
    script = f'''
import sys, time
sys.path.insert(0, "tests")
from test_rssi_stats import SequenceBackend, record
from lswifi import app, appsetup

class Slow(SequenceBackend):
    def scan(self, iface):
        if self.calls == 0:
            self.calls += 1
            return [record(-57)]
        print("ready", flush=True)
        time.sleep(60)
        return []

backend = Slow([[record(-57)], []])
args = appsetup.setup_parser().parse_args(
    ["-bssid", "{BSSID_A}", "-all", "--rssi-stats", "-n", "2", "-i", "0",
     "--json", r"{path}"]
)
appsetup.setup_logger(args)
app.run(args, backend=backend)
'''
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parent.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for line in proc.stdout:
        if line.strip() == "ready":
            break
    time.sleep(0.5)
    proc.send_signal(signal.SIGINT)
    try:
        out, err = proc.communicate(timeout=10)
    finally:
        proc.kill()
    assert proc.returncode == 130
    rows = summary_rows(out)
    assert (rows["samples"], rows["mean"], rows["range"]) == (
        "1 of 1 scan",
        "-57.0 dBm",
        "0 dB (min -57, max -57 dBm)",
    )
    assert "Traceback" not in err
    assert "rssi_stats" not in json.loads(path.read_text())


HIDDEN = "--rssi-stats stopped: macOS returned scan results without BSSIDs"


def hidden_record(rssi_dbm=-60):
    return BssRecord(ssid=b"", bssid="", frequency_mhz=5180, rssi_dbm=rssi_dbm)


class HiddenBackend(SequenceBackend):
    def open_session(self, args, iface):
        return macos.MacOSScanSession(self, iface, args)


@pytest.fixture
def hidden_message(monkeypatch):
    monkeypatch.setattr(macos_location, "bssid_hidden_message", lambda: HIDDEN)


class TestRssiStatsCannotMatch:
    def test_hidden_bssid_without_bssid_exits_2_after_one_scan(
        self, hidden_message, capsys, caplog
    ):
        backend = HiddenBackend([[hidden_record()]] * 3)
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["--rssi-stats", "-i", "0", "-n", "3"]), backend=backend)
        assert exited.value.code == 2
        assert backend.calls == 1
        assert HIDDEN in caplog.text
        assert "sample 1/3" not in capsys.readouterr().out

    def test_hidden_bssid_with_bssid_exits_2_after_one_scan(
        self, hidden_message, tmp_path, caplog
    ):
        backend = HiddenBackend([[hidden_record()]] * 3)
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "3", "--json", str(path)), backend=backend)
        assert exited.value.code == 2
        assert backend.calls == 1
        assert HIDDEN in caplog.text
        assert not path.exists() or "rssi_stats" not in path.read_text()

    def test_connected_ap_never_seen_exits_2(self, tmp_path, caplog):
        limit = rssistats.MISS_LIMIT
        backend = SequenceBackend([[record(-50, bssid=BSSID_B)]] * limit)
        path = tmp_path / "out.json"
        args = parse(["--rssi-stats", "-i", "0", "-n", "3", "--json", str(path)])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 2
        assert backend.calls == limit
        assert f"not heard in the last {limit} scans" in caplog.text
        assert f"the connected BSSID was not seen in {limit} scans" in caplog.text
        assert not path.exists() or "rssi_stats" not in path.read_text()


BSSID_C = "00:00:5e:00:53:03"
BSSID_OTHER = "00:00:5f:00:53:04"


class TestPrefixMatch:
    def test_prefix_matches_every_bssid_starting_with_it(self):
        assert rssistats.matches_bssid("00:00:5E", BSSID_A)
        assert rssistats.matches_bssid("00-00-5e-00", BSSID_B)
        assert not rssistats.matches_bssid("00:00:5e", BSSID_OTHER)
        assert not rssistats.matches_bssid(BSSID_A, "00:00:5e:00:53:011")

    def test_table_sorts_strongest_first_then_by_stdev_then_stale(self):
        def summary(bssid, values, scans=4, band="5 GHz"):
            samples = {(IFACE_MAC, bssid, band): [("t", v) for v in values]}
            return rssistats.summarize(samples, scans)[0]

        stale_once = summary(BSSID_C, [-50])
        stale_flat = summary("00:00:5e:00:53:05", [-58, -58], scans=6)
        summaries = [
            summary(BSSID_A, [-60, -70, -80]),
            stale_once,
            summary(BSSID_B, [-70, -70, -70]),
            stale_flat,
            summary(BSSID_OTHER, [-60, -60, -60]),
        ]
        text = rssistats.format_table(summaries)
        rows = table_rows(text)
        assert [row["BSSID"] for row in rows] == [
            BSSID_OTHER,
            BSSID_B,
            BSSID_A,
            BSSID_C,
            "00:00:5e:00:53:05",
        ]
        assert [row["samples"] for row in rows[-2:]] == ["1/4*", "2/6*"]
        assert (rows[-2]["stdev"], rows[-2]["AP name"]) == ("-", "-")
        assert "CV" not in rows[-2]
        assert rows[2]["range"] == "20 (-80..-60)"
        assert rows[1]["range"] == "0 (-70..-70)"
        assert text.splitlines()[0] == "RSSI stats"
        assert text.splitlines()[1].split("  ")[-3:] == [
            "mean dBm",
            "stdev dB",
            "range dB",
        ]
        assert "stead" not in text
        assert (
            "* possibly stale: heard in fewer than 2 samples, or the same reading "
            "in every sample while heard in fewer than half the samples"
        ) in text
        assert "* possibly stale:" in text
        assert "possibly stale" not in rssistats.format_table(summaries[:1])

    @pytest.mark.parametrize(
        ("values", "scans", "stale"),
        [
            ([-60], 1, True),
            ([-58] * 6, 30, True),
            ([-58] * 15, 30, False),
            ([-58, -59], 30, False),
            ([-58] * 30, 30, False),
        ],
    )
    def test_possibly_stale_rule(self, values, scans, stale):
        assert rssistats.is_possibly_stale(values, scans) is stale

    def test_prefix_run_prints_plan_compact_progress_and_table(
        self, tmp_path, capsys, caplog, monkeypatch
    ):
        caplog.set_level(logging.INFO)
        fake_clock(monkeypatch, 3)
        scans = [
            [
                record(-60),
                record(-70, bssid=BSSID_B),
                record(-50, bssid=BSSID_C, frequency_mhz=2412),
                record(-40, bssid=BSSID_OTHER),
            ],
            [record(-62), record(-70, bssid=BSSID_B)],
            [
                record(-64),
                record(-70, bssid=BSSID_B),
                record(-52, bssid=BSSID_C, frequency_mhz=2412),
            ],
        ]
        path = tmp_path / "out.json"
        args = parse(
            [
                "--rssi-stats",
                "-bssid",
                "00:00:5e",
                "-n",
                "3",
                "-i",
                "2",
                "--json",
                str(path),
            ]
        )
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=SequenceBackend(scans))
        assert exited.value.code == 0
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert lines.pop(0) == (
            "waiting for the first scan to find the matching BSSIDs..."
        )
        assert lines[0] == (
            "matched 3 BSSIDs on 2 bands; measuring 3 samples, Ctrl-C to stop"
        )
        assert progress(out)[:3] == [
            "sample 1/3  seen 3/3",
            "sample 2/3  seen 2/3",
            "sample 3/3  seen 3/3",
        ]
        timed = [line for line in lines if re.match(r"\d\d:\d\d:\d\d ", line)]
        assert "(+" not in timed[0]
        assert all(re.search(r" \(\+\d+ s\)$", line) for line in timed[1:3])
        assert BSSID_OTHER not in out
        rows = table_rows(out)
        assert [(row["BSSID"], row["band"], row["samples"]) for row in rows] == [
            (BSSID_C, "2.4 GHz", "2/3"),
            (BSSID_A, "5 GHz", "3/3"),
            (BSSID_B, "5 GHz", "3/3"),
        ]
        footer = {
            line[2:12].strip(): line[13:]
            for line in out[out.index("RSSI stats\nSSID ") :].splitlines()
            if line.startswith("  ")
        }
        assert footer["samples"] == "3 of 3 scans"
        clocks = [line[:8] for line in timed[:3]]
        assert footer["time"].startswith(f"{clocks[0]} to {clocks[2]} (")
        assert re.fullmatch(r"about \d+ s between samples", footer["interval"])
        assert IFACE_MAC in footer["interface"]
        assert "total number of completed scans" not in caplog.text
        stats = json.loads(path.read_text())["rssi_stats"]
        assert sorted((e["bssid"], e["band"], e["samples"]) for e in stats) == [
            (BSSID_A, "5 GHz", 3),
            (BSSID_B, "5 GHz", 3),
            (BSSID_C, "2.4 GHz", 2),
        ]
        assert all(None not in e.values() for e in stats)
        assert all("cv" not in e for e in stats)

    def test_prefix_with_one_match_uses_the_table_from_scan_1(self, tmp_path, capsys):
        scans = [[record(-60), record(-40, bssid=BSSID_OTHER)], [record(-62)]]
        path = tmp_path / "out.json"
        args = parse(
            [
                "--rssi-stats",
                "-bssid",
                "00:00:5e",
                "-n",
                "2",
                "-i",
                "0",
                "--json",
                str(path),
            ]
        )
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=SequenceBackend(scans))
        assert exited.value.code == 0
        lines = capsys.readouterr().out.splitlines()
        assert lines.pop(0) == (
            "waiting for the first scan to find the matching BSSIDs..."
        )
        assert lines[0] == (
            "matched 1 BSSID on 1 band; measuring 2 samples, Ctrl-C to stop"
        )
        assert lines[1][9:].startswith("sample 1/2  seen 1/1")
        assert lines[2][9:].startswith("sample 2/2  seen 1/1")
        assert [row["BSSID"] for row in table_rows("\n".join(lines))] == [BSSID_A]
        stats = json.loads(path.read_text())["rssi_stats"]
        assert "possibly_stale" not in stats[0]

    def test_second_bssid_appearing_later_keeps_the_table_layout(self, capsys):
        scans = [[record(-60)], [record(-62), record(-70, bssid=BSSID_B)]]
        args = parse(["--rssi-stats", "-bssid", "00:00:5e", "-n", "2", "-i", "0"])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        lines = capsys.readouterr().out.splitlines()
        assert lines.pop(0) == (
            "waiting for the first scan to find the matching BSSIDs..."
        )
        assert lines[0].startswith("matched 1 BSSID on 1 band;")
        assert lines[1][9:].startswith("sample 1/2  seen 1/1")
        assert lines[2][9:].startswith("sample 2/2  seen 2/2")
        assert sum(line.startswith("matched") for line in lines) == 1
        rows = table_rows("\n".join(lines))
        assert [(row["BSSID"], row["samples"]) for row in rows] == [
            (BSSID_A, "2/2"),
            (BSSID_B, "1/2*"),
        ]

    def test_exact_bssid_keeps_the_single_layout_from_scan_1(self, capsys):
        scans = [[record(-60)], [record(-62)]]
        with pytest.raises(SystemExit):
            app.run(stats_args("-n", "2"), backend=SequenceBackend(scans))
        out = capsys.readouterr().out
        assert re.search(r"^measuring 2 samples, Ctrl-C to stop$", out, re.M)
        assert re.search(r"^\d\d:\d\d:\d\d sample 1/2: -60 dBm$", out, re.M)
        assert "matched" not in out
        assert summary_rows(out)["BSSID"] == BSSID_A

    def test_stale_row_sets_possibly_stale_in_json(self, tmp_path):
        scans = [[record(-60), record(-58, bssid=BSSID_B)]] + [
            [record(v)] for v in (-61, -62, -60, -63)
        ]
        path = tmp_path / "out.json"
        args = parse(
            [
                "--rssi-stats",
                "-bssid",
                "00:00:5e",
                "-n",
                "5",
                "-i",
                "0",
                "--json",
                str(path),
            ]
        )
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        stats = {e["bssid"]: e for e in json.loads(path.read_text())["rssi_stats"]}
        assert stats[BSSID_B]["possibly_stale"] is True
        assert "possibly_stale" not in stats[BSSID_A]

    def test_band_warning_says_row_in_table_mode(self, caplog):
        scans = [
            [record(-40, frequency_mhz=2412), record(-60)],
            [record(-42, frequency_mhz=2412), record(-62)],
        ]
        args = parse(["--rssi-stats", "-bssid", "00:00:5e", "-n", "2", "-i", "0"])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        assert "each band has its own row." in caplog.text


class TestFreshReadings:
    def test_first_call_only_seeds_markers(self):
        tracker = rssistats.Freshness()
        assert not tracker.observe({("a", "5180"): 1, ("b", "5180"): 1}, 0.0)
        assert not tracker.observe({("a", "5180"): 1, ("b", "5180"): 1}, 2.0)
        assert tracker.observe({("a", "5180"): 1, ("b", "5180"): 2}, 4.0)
        assert (tracker.scan_calls, tracker.real_scans) == (3, 1)
        assert not tracker.is_fresh_reading(("a", "5180"), 1)
        assert tracker.is_fresh_reading(("b", "5180"), 2)

    def test_backend_real_scan_flag_decides_the_call(self):
        tracker = rssistats.Freshness()
        assert tracker.observe({("a", "5180"): 1}, 0.0, real=True)
        assert not tracker.observe({("a", "5180"): 2}, 2.0, real=False)
        assert tracker.observe({("a", "5180"): 3}, 17.0, real=True)
        assert (tracker.scan_calls, tracker.real_scans) == (3, 2)

    def test_reading_counts_only_when_its_marker_changes(self):
        tracker = rssistats.Freshness()
        assert tracker.is_fresh_reading(("a", "5180"), 1)
        assert not tracker.is_fresh_reading(("a", "5180"), 1)
        assert tracker.is_fresh_reading(("a", "5180"), 2)

    def test_no_markers_counts_every_scan(self):
        tracker = rssistats.Freshness()
        assert tracker.observe({("a", "5180"): None}, 0.0)
        assert tracker.observe({("a", "5180"): None}, 1.0)
        assert not tracker.has_markers
        assert tracker.is_fresh_reading(("a", "5180"), None)

    def test_seeded_marker_is_not_fresh_on_the_first_real_scan(self):
        scanner = app.lswifi()
        bss = WirelessNetworkBss(record(-60, last_seen=1))
        client = SimpleNamespace(
            mac=IFACE_MAC,
            data=[bss],
            real_scan=None,
            last_scan_time_iso="2026-11-05T00:00:00.000-05:00",
        )
        scanner.observe_rssi_scan(client)
        assert scanner.rssi_call_fresh[IFACE_MAC] is False
        client.real_scan = True
        scanner.observe_rssi_scan(client)
        assert scanner.rssi_call_fresh[IFACE_MAC] is True
        assert not scanner.is_fresh_rssi_reading(IFACE_MAC, bss)

    def test_gaps_and_span_agree_with_the_printed_clock(self):
        tracker = rssistats.Freshness()
        times = [
            ("00:01:15.900", True),
            ("00:01:39.100", False),
            ("00:02:04.950", True),
            ("00:02:29.020", True),
        ]
        gaps = []
        for index, (at, measured) in enumerate(times):
            iso = f"2026-11-04T{at}-05:00"
            tracker.observe({("a", "5180"): index}, float(index), real=True, at=iso)
            tracker.record(measured)
            if measured:
                gaps.append(tracker.sample_gap)
        assert gaps == [None, 49, 25]
        run = rssistats.RunInfo(
            started_at=tracker.started_at, ended_at=tracker.ended_at
        )
        assert rssistats.format_span(run) == "00:01:15 to 00:02:29 (74 s)"
        assert sum(gap for gap in gaps if gap) == 74

    def test_interval_is_the_mean_gap_between_samples(self):
        def summary(*clocks):
            entries = [(f"2026-11-04T{c}-05:00", -60) for c in clocks]
            return rssistats.summarize({("m", "b", "5 GHz"): entries}, len(entries))[0]

        two = summary("00:01:15.900", "00:02:04.950", "00:02:29.020")
        assert rssistats.format_interval(two) == "about 37 s between samples"
        assert rssistats.summary_to_json(two)["interval_s"] == 37.0
        one = summary("00:01:15.900")
        assert rssistats.format_interval(one) == ""
        assert "interval_s" not in rssistats.summary_to_json(one)
        assert "interval" not in rssistats.format_summary(one)
        half = summary("00:00:00", "00:00:24", "00:00:49")
        assert rssistats.format_interval(half) == "about 25 s between samples"
        assert rssistats.summary_to_json(half)["interval_s"] == 24.5

    def test_waiting_line_comes_first(self, capsys):
        scans = [[record(-60)], [record(-62)]]
        with pytest.raises(SystemExit):
            app.run(stats_args("-n", "2"), backend=SequenceBackend(scans))
        out = capsys.readouterr().out
        assert out.startswith(
            "waiting for the first scan to identify the AP...\ntarget\n"
        )
        assert "steady" not in out.lower()

    def test_interface_row_names_the_interface(self):
        label = rssistats.RssiLabel(ssid="ExampleNet")
        text = rssistats.format_target(IFACE_MAC, BSSID_A, "5 GHz", label, "en0")
        assert f"  interface  en0 ({IFACE_MAC})" in text.splitlines()
        assert rssistats.format_interface("", IFACE_MAC) == IFACE_MAC

    def test_progress_shows_the_gap_after_the_first_sample(self):
        at = "2026-11-04T00:01:39.000-05:00"
        assert rssistats.format_progress(at, 1, 5, ["-62 dBm"]) == (
            "00:01:39 sample 1/5: -62 dBm"
        )
        assert rssistats.format_progress(at, 2, 5, ["-65 dBm"], 24.4) == (
            "00:01:39 sample 2/5: -65 dBm (+24 s)"
        )

    def test_samples_row_counts_only_scans(self):
        def summary(samples, scans):
            return rssistats.summarize(
                {("m", "b", "5 GHz"): [("t", -60)] * samples}, scans
            )[0]

        assert rssistats.format_samples(summary(1, 1)) == "1 of 1 scan"
        assert rssistats.format_samples(summary(18, 20)) == "18 of 20 scans, 2 missed"

    def test_run_keeps_scanning_until_n_samples(self, tmp_path, capsys, caplog):
        caplog.set_level(logging.INFO)
        scans = [
            [record(-60, last_seen=1)],
            [record(-60, last_seen=1)],
            [record(-62, last_seen=2)],
            [record(-62, last_seen=2)],
            [record(-63, last_seen=3)],
            [record(-63, last_seen=3)],
            [record(-61, last_seen=4)],
        ]
        backend = SequenceBackend(scans)
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.lswifi().run(
                stats_args("-n", "3", "--json", str(path)), backend=backend
            )
        assert exited.value.code == 0
        assert backend.calls == 7
        out = capsys.readouterr().out
        assert [line for line in progress(out) if line.startswith("sample")] == [
            "sample 1/3: -62 dBm",
            "sample 2/3: -63 dBm",
            "sample 3/3: -61 dBm",
        ]
        assert "the OS returns" not in out
        assert "scan call" not in out
        assert out.index("measuring 3 samples") < out.index("sample 1/3")
        rows = summary_rows(out)
        assert rows["samples"] == "3 of 3 scans"
        assert re.fullmatch(r"\d\d:\d\d:\d\d to \d\d:\d\d:\d\d \(\d+ s\)", rows["time"])
        assert caplog.text.count("exporting scans as JSON") == 1
        document = json.loads(path.read_text())
        stats = document["rssi_stats"][0]
        assert (stats["samples"], stats["completed_scans"], stats["scan_calls"]) == (
            3,
            3,
            7,
        )
        assert [r["rssi_dbm"] for r in stats["readings"]] == [-62, -63, -61]
        assert all(
            re.search(r"[+-]\d\d:\d\d$", r["timestamp"]) for r in stats["readings"]
        )
        assert re.search(r"[+-]\d\d:\d\d$", stats["started"])
        assert re.search(r"[+-]\d\d:\d\d$", stats["ended"])
        assert "missed" not in stats
        assert "every_scan_counted" not in stats
        assert len(document["scan_data"]) == 7

    def test_target_not_heard_in_a_real_scan_is_a_miss(self, tmp_path, capsys):
        scans = [
            [record(-60, last_seen=1), record(-70, bssid=BSSID_B, last_seen=1)],
            [record(-61, last_seen=2), record(-70, bssid=BSSID_B, last_seen=1)],
            [record(-61, last_seen=2), record(-72, bssid=BSSID_B, last_seen=2)],
            [record(-62, last_seen=3), record(-72, bssid=BSSID_B, last_seen=2)],
            [record(-63, last_seen=4), record(-72, bssid=BSSID_B, last_seen=2)],
        ]
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit):
            app.lswifi().run(
                stats_args("-n", "3", "--json", str(path)),
                backend=SequenceBackend(scans),
            )
        out = capsys.readouterr().out
        assert progress(out)[:4] == [
            "sample 1/3: -61 dBm",
            "not heard in this scan (1 missed so far)",
            "sample 2/3: -62 dBm",
            "sample 3/3: -63 dBm",
        ]
        assert summary_rows(out)["samples"] == "3 of 4 scans, 1 missed"
        stats = json.loads(path.read_text())["rssi_stats"][0]
        assert stats["missed"] == 1

    def test_no_new_scan_stops_after_the_idle_limit(self, caplog):
        limit = rssistats.IDLE_LIMIT
        scans = [[record(-60, last_seen=1)]] * (limit + 1)
        backend = SequenceBackend(scans)
        with pytest.raises(SystemExit) as exited:
            app.lswifi().run(stats_args("-n", "3"), backend=backend)
        assert exited.value.code == 2
        assert backend.calls == limit
        assert f"no new scan in the last {limit} scan calls" in caplog.text


class TestRealScan:
    def test_short_call_is_a_cached_answer(self):
        assert not macos.is_real_scan(0.06)
        assert macos.is_real_scan(13.8)


class TestIncludeTargets:
    def scans(self):
        return [
            [
                record(-60, ssid=b"Lab"),
                record(-50, bssid=BSSID_B, ssid=b"Lab-IoT", frequency_mhz=2412),
                record(-55, bssid=BSSID_B, ssid=b"Lab-IoT"),
                record(-40, bssid=BSSID_OTHER, ssid=b"Other", connected=True),
            ],
            [
                record(-62, ssid=b"Lab"),
                record(-52, bssid=BSSID_B, ssid=b"Lab-IoT", frequency_mhz=2412),
                record(-57, bssid=BSSID_B, ssid=b"Lab-IoT"),
                record(-41, bssid=BSSID_OTHER, ssid=b"Other", connected=True),
            ],
        ]

    def run(self, capsys, *extra, scans=None):
        args = parse(["--rssi-stats", "-n", "2", "-i", "0", *extra])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=SequenceBackend(scans or self.scans()))
        return exited.value.code, capsys.readouterr().out

    def test_include_tracks_every_matching_ssid_per_band_in_the_table(self, capsys):
        code, out = self.run(capsys, "-include", "Lab")
        assert code == 0
        lines = out.splitlines()
        assert lines[0] == "waiting for the first scan to find the matching BSSIDs..."
        assert lines[1] == (
            "matched 3 BSSIDs on 2 bands; measuring 2 samples, Ctrl-C to stop"
        )
        rows = table_rows(out)
        assert [(row["SSID"], row["BSSID"], row["band"]) for row in rows] == [
            ("Lab-IoT", BSSID_B, "2.4 GHz"),
            ("Lab-IoT", BSSID_B, "5 GHz"),
            ("Lab", BSSID_A, "5 GHz"),
        ]
        assert BSSID_OTHER not in out
        assert "  samples    2 of 2 scans" in lines

    def test_include_and_bssid_narrow_together(self, capsys):
        code, out = self.run(capsys, "-include", "Lab", "-bssid", BSSID_A)
        assert code == 0
        assert [row["BSSID"] for row in table_rows(out)] == [BSSID_A]

    def test_exclude_still_applies(self, capsys):
        code, out = self.run(capsys, "-include", "Lab", "-exclude", "IoT")
        assert code == 0
        assert [row["SSID"] for row in table_rows(out)] == ["Lab"]

    def test_include_with_no_match_exits_2(self, capsys, caplog):
        scans = [[record(-40, ssid=b"Other", connected=True)]] * rssistats.MISS_LIMIT
        args = parse(["--rssi-stats", "-n", "2", "-i", "0", "-include", "Nope"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=SequenceBackend(scans))
        assert exited.value.code == 2
        assert "no samples matched -include Nope" in caplog.text
