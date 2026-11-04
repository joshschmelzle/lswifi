import json
import logging
import signal
import subprocess
import sys
import time
from pathlib import Path

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


def record(rssi_dbm, bssid=BSSID_A, connected=False, frequency_mhz=5180):
    return BssRecord(
        ssid=SSID,
        bssid=bssid,
        frequency_mhz=frequency_mhz,
        rssi_dbm=rssi_dbm,
        connected=connected,
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


def summary_rows(text):
    block = text[text.index("RSSI stats") :].split("\n\n")[0]
    rows = {}
    for line in block.splitlines()[1:]:
        name, _, value = line.strip().partition("  ")
        rows.setdefault(name, value.strip())
    return rows


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

    def test_cv_is_zero_for_a_flat_link(self):
        assert rssistats.cv_pct([-60, -60, -60]) == 0.0

    def test_cv_is_stdev_over_absolute_mean_dbm(self):
        assert rssistats.cv_pct([-60, -62, -64]) == 3.2

    def test_cv_grows_with_the_spread(self):
        steady = rssistats.cv_pct([-60, -61, -60, -61])
        jumpy = rssistats.cv_pct([-60, -66, -60, -66])
        assert steady is not None and jumpy is not None
        assert jumpy > steady

    def test_cv_needs_two_samples(self):
        assert rssistats.cv_pct([-60]) is None

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
            cv=1.6,
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
            "cv",
            "min_dbm",
            "max_dbm",
            "spread_db",
        }
        assert None not in obj.values()
        assert (obj["channel"], obj["channel_width"]) == (36, 20)
        assert obj["cv"] == 1.6
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
            "1/1 scans",
        )
        assert BSSID_B not in out

    def test_rssi_stats_without_all_keeps_weak_readings(self, monkeypatch, capsys):
        backend = SequenceBackend([[record(-60)], [record(-90)]])
        argv = ["-bssid", BSSID_A, "--rssi-stats", "-n", "2", "-i", "0"]
        assert run_main(monkeypatch, backend, argv) == 0
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["samples"], rows["mean"]) == ("2/2 scans", "-75.0 dBm")

    def test_defaults_to_30_scans_two_seconds_apart(self, monkeypatch, capsys):
        sleeps = []
        monkeypatch.setattr(app.time, "sleep", sleeps.append)
        backend = SequenceBackend([[record(-60, connected=True)]] * 30)
        assert run_main(monkeypatch, backend, ["--rssi-stats"]) == 0
        assert backend.calls == 30
        assert sleeps.count(2) == 29
        assert summary_rows(capsys.readouterr().out)["samples"] == "30/30 scans"

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

    @pytest.mark.parametrize("value", ["00:00:5e", "00:00:5e:00:53"])
    def test_partial_bssid_is_rejected(self, monkeypatch, capsys, value):
        backend = SequenceBackend([[record(-60)]])
        argv = ["--rssi-stats", "-bssid", value]
        assert run_main(monkeypatch, backend, argv) == 2
        assert "--rssi-stats needs a full BSSID for -bssid" in capsys.readouterr().err
        assert backend.calls == 0

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

    def test_progress_replaces_the_table(self, capsys):
        scans = [[record(-60, connected=True)], [], [record(-64, connected=True)]]
        args = parse(["--rssi-stats", "-i", "0", "-n", "3"])
        with pytest.raises(SystemExit):
            app.run(args, backend=SequenceBackend(scans))
        out = capsys.readouterr().out
        assert out.splitlines()[:3] == [
            "scan 1/3: -60 dBm",
            "scan 2/3: not seen",
            "scan 3/3: -64 dBm",
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
            "samples",
            "mean",
            "stdev",
            "CV",
            "min",
            "max",
            "spread",
            "interface",
        ]
        assert rows["stdev"] == "2.0 dB"
        assert rows["CV"] == "3.2%"
        assert (rows["min"], rows["max"], rows["spread"]) == (
            "-64 dBm",
            "-60 dBm",
            "4 dB",
        )
        assert rows["interface"] == IFACE_MAC

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
        assert summary_rows(capsys.readouterr().out)["samples"] == "1/1 scans"

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
            "3/3 scans",
            "-62.0 dBm",
            "2.0 dB",
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
            "cv",
            "min_dbm",
            "max_dbm",
            "spread_db",
        }
        assert isinstance(stats["min_dbm"], int)
        assert isinstance(stats["max_dbm"], int)
        assert isinstance(stats["spread_db"], int)
        assert isinstance(stats["cv"], float)
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
        assert "scan 1/2: -40 dBm (2.4 GHz), -60 dBm (5 GHz)" in out
        blocks = out[out.index("RSSI stats") :].split("\n\n")
        assert len(blocks) == 2
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

    def test_missing_scan_counts_as_completed(self, capsys):
        backend = SequenceBackend([[record(-60)], [], [record(-64)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "3", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        assert summary_rows(capsys.readouterr().out)["samples"] == "2/3 scans"

    def test_weak_rssi_below_default_threshold_counts(self, capsys):
        backend = SequenceBackend([[record(-60)], [record(-90)], [record(-62)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "3", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        assert summary_rows(capsys.readouterr().out)["samples"] == "3/3 scans"

    def test_one_scan_no_stdev(self, capsys):
        backend = SequenceBackend([[record(-60)]])
        with pytest.raises(SystemExit) as exited:
            app.run(stats_args("-n", "1", "-i", "0"), backend=backend)
        assert exited.value.code == 0
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["mean"], rows["spread"]) == ("-60.0 dBm", "0 dB")
        assert "stdev" not in rows
        assert "CV" not in rows

    def test_no_match_exits_2_and_creates_no_json(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[]])
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("--json", str(path), "-n", "1", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 2
        assert f"no samples matched -bssid {BSSID_A} in 1 scans" in caplog.text
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
    assert (rows["samples"], rows["mean"], rows["spread"]) == (
        "1/1 scans",
        "-57.0 dBm",
        "0 dB",
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
        assert "scan 1/3" not in capsys.readouterr().out

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
        backend = SequenceBackend([[record(-50, bssid=BSSID_B)]] * 3)
        path = tmp_path / "out.json"
        args = parse(["--rssi-stats", "-i", "0", "-n", "3", "--json", str(path)])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 2
        assert backend.calls == 3
        assert "the connected BSSID was not seen in 3 scans" in caplog.text
        assert not path.exists() or "rssi_stats" not in path.read_text()
