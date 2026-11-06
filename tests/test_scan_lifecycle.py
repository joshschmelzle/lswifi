import builtins
import json
import logging
import os
import stat
import sys

import pytest

from lswifi import __main__ as lswifi_main
from lswifi import app, helpers, rssistats
from lswifi.backends.base import BackendError
from tests.test_backends import parse
from tests.test_rssi_stats import (
    BSSID_A,
    BSSID_B,
    SequenceBackend,
    record,
    run_main,
    summary_rows,
)


class FailingBackend(SequenceBackend):
    """Returns scans in order; an exception in the list is raised instead"""

    def scan(self, iface):
        result = self.scans[self.calls]
        self.calls += 1
        if isinstance(result, BaseException):
            raise result
        return list(result)


def json_rows(path):
    return [
        (row["bssid"], row["rssi"]) for row in json.loads(path.read_text())["scan_data"]
    ]


class TestFailedScans:
    @pytest.mark.parametrize(
        "error",
        [BackendError("scan failed: test"), RuntimeError("unexpected: test")],
    )
    def test_failed_scan_is_logged_and_not_replayed(self, tmp_path, caplog, error):
        backend = FailingBackend(
            [[record(-51, bssid=BSSID_A)], error, [record(-53, bssid=BSSID_B)]]
        )
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["-n", "3", "-i", "0", "--json", str(path)]), backend=backend)
        assert exited.value.code == 0
        assert backend.calls == 3
        assert json_rows(path) == [(BSSID_A, "-51"), (BSSID_B, "-53")]
        assert "test" in caplog.text
        assert "no scan data" not in caplog.text

    def test_failed_scan_counts_as_no_new_scan_in_rssi_stats(self, capsys):
        backend = FailingBackend(
            [
                [record(-60, last_seen=1)],
                BackendError("scan failed: test"),
                [record(-62, last_seen=2)],
                [record(-64, last_seen=3)],
            ]
        )
        args = parse(["--rssi-stats", "-bssid", BSSID_A, "-n", "2", "-i", "0"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 0
        assert backend.calls == 4
        rows = summary_rows(capsys.readouterr().out)
        assert (rows["samples"], rows["mean"]) == ("2 of 2 scans", "-63.0 dBm")

    def test_failed_call_keeps_the_baseline(self):
        tracker = rssistats.Freshness()
        assert not tracker.observe({("a", "5180"): 1}, 0.0)
        tracker.failed_call(1.0)
        assert tracker.idle_streak == 2
        assert not tracker.observe({("a", "5180"): 1}, 2.0)
        assert tracker.observe({("a", "5180"): 2}, 3.0)
        assert (tracker.scan_calls, tracker.real_scans) == (4, 1)


class TestRssiStatsRejectsOutputModes:
    @pytest.mark.parametrize(
        ("argv", "named"),
        [
            (["-ies", BSSID_A], "-ies is"),
            (["--bytes", BSSID_A], "--bytes is"),
            (["-export"], "-export is"),
            (["-exportraw"], "-exportraw is"),
            (["-export", "-exportraw"], "-export, -exportraw are"),
        ],
    )
    def test_rejected_before_any_scan(self, monkeypatch, capsys, argv, named):
        backend = SequenceBackend([[record(-60, connected=True)]])
        assert run_main(monkeypatch, backend, ["--rssi-stats", *argv]) == 2
        assert f"{named} incompatible with --rssi-stats" in capsys.readouterr().err
        assert backend.calls == 0


class TestRssiStatsFinish:
    def test_interrupt_after_the_report_does_not_report_again(self, capsys):
        scanner = app.lswifi()
        scanner.rssi_samples = {
            ("00:00:5e:00:53:aa", BSSID_A, "5 GHz"): [("2026-01-01T00:00:00", -60)]
        }
        args = parse(["--rssi-stats", "-bssid", BSSID_A])
        assert scanner.finish_rssi_run(args)
        scanner.report_interrupted_scans(args)
        assert capsys.readouterr().out.count("RSSI stats") == 1

    def test_timed_run_does_not_claim_it_stopped(self, monkeypatch, caplog, capsys):
        clock = {"now": 1_000_000.0}
        monkeypatch.setattr(app.time, "time", lambda: clock["now"])
        monkeypatch.setattr(
            app.time,
            "sleep",
            lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
        )
        scans = [[record(-60)]] + [[]] * 12 + [[record(-62)], [record(-64)]]
        backend = SequenceBackend(scans)
        args = parse(["--rssi-stats", "-bssid", BSSID_A, "--time", "30", "-i", "2"])
        with pytest.raises(SystemExit) as exited:
            app.run(args, backend=backend)
        assert exited.value.code == 0
        assert backend.calls == 15
        assert "stopping" not in caplog.text
        assert "waiting for the first scan" in capsys.readouterr().out


class TestRunMode:
    @pytest.mark.parametrize(
        ("argv", "mode"),
        [
            ([], app.RunMode.SCAN),
            (["-decoderaw", "x.ies", "-decode", "x.pcap"], app.RunMode.DECODE_RAW),
            (["-decode", "x.pcap", "--watchevents"], app.RunMode.DECODE_PCAP),
            (["--watchevents", "--list-interfaces"], app.RunMode.WATCH),
            (["--list-interfaces", "--display-ethers"], app.RunMode.LIST_INTERFACES),
            (["--append-ethers", "a,b", "--display-ethers"], app.RunMode.APPEND_ETHERS),
            (["--display-ethers", "-ap"], app.RunMode.DISPLAY_ETHERS),
            (["-ap"], app.RunMode.INTERFACE_INFO),
            (["--get-interfaces"], app.RunMode.INTERFACE_INFO),
        ],
    )
    def test_precedence(self, argv, mode):
        assert app.run_mode(parse(argv)) is mode


@pytest.fixture
def data_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    directory = tmp_path / "lswifi"
    directory.mkdir()
    return directory


class TestApNames:
    @pytest.mark.parametrize(
        ("argv", "acknowledged", "mode"),
        [
            ([], False, app.ApNames.OFF),
            (["--ap-names"], False, app.ApNames.OFF),
            (["--ap-names"], True, app.ApNames.CACHE),
            (["-ethers"], False, app.ApNames.ETHERS),
            (["-ethers", "--ap-names"], True, app.ApNames.ETHERS),
        ],
    )
    def test_mode(self, argv, acknowledged, mode):
        assert app.ap_names_mode(parse(argv), acknowledged) is mode

    def test_ethers_alone_shows_the_ap_name_column(self, data_home, capsys):
        (data_home / "ethers").write_text(f"{BSSID_A} LAB-AP-1\n")
        backend = SequenceBackend([[record(-60, bssid=BSSID_A)]])
        with pytest.raises(SystemExit):
            app.run(parse(["-ethers", "-n", "1"]), backend=backend)
        out = capsys.readouterr().out
        assert "AP NAME" in out
        assert "LAB-AP-1" in out

    def test_blank_and_one_word_ethers_lines_are_skipped(self, data_home, caplog):
        (data_home / "ethers").write_text(f"\n{BSSID_A} LAB-AP-1\n   \n{BSSID_B}\n")
        assert app.lswifi().loadEthers() == {BSSID_A: "LAB-AP-1"}
        assert "line 4" in caplog.text

    def test_prompt_without_input_leaves_caching_off(
        self, data_home, monkeypatch, caplog
    ):
        def no_input(_prompt=""):
            raise EOFError

        monkeypatch.setattr(builtins, "input", no_input)
        assert lswifi_main.user_ack_apnames_disclaimer() is False
        assert "caching stays off" in caplog.text
        assert not (data_home / "apnames.ack").exists()


class TestWriteJson:
    def test_creates_a_missing_file(self, tmp_path):
        path = tmp_path / "out.json"
        helpers.write_json(str(path), {"a": 1}, None)
        assert json.loads(path.read_text()) == {"a": 1}

    def test_failed_write_keeps_the_old_file(self, tmp_path, monkeypatch):
        path = tmp_path / "out.json"
        path.write_text('{"scan_data": [1, 2, 3]}')

        def fail(document, file, indent=None):
            file.write('{"scan_data": [1,')
            raise KeyboardInterrupt

        monkeypatch.setattr(helpers.json, "dump", fail)
        with pytest.raises(KeyboardInterrupt):
            helpers.write_json(str(path), {"scan_data": [1, 2, 3, 4]}, None)
        assert json.loads(path.read_text()) == {"scan_data": [1, 2, 3]}
        assert os.listdir(tmp_path) == ["out.json"]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
    def test_replacing_keeps_the_file_mode(self, tmp_path):
        path = tmp_path / "out.json"
        path.write_text("{}")
        path.chmod(0o644)
        helpers.write_json(str(path), {"a": 1}, None)
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_failed_scan_logs_at_error_level(caplog):
    caplog.set_level(logging.ERROR)
    backend = FailingBackend([BackendError("scan failed: test")])
    with pytest.raises(SystemExit):
        app.run(parse(["-n", "1"]), backend=backend)
    assert any(
        record.levelno == logging.ERROR and "scan failed: test" in record.getMessage()
        for record in caplog.records
    )


class TestConnectedMarker:
    @pytest.mark.parametrize("extra", [[], ["--csv"], ["--json"]])
    def test_table_marks_the_connected_bssid(self, tmp_path, capsys, extra):
        outputs = {
            "--csv": str(tmp_path / "out.csv"),
            "--json": str(tmp_path / "out.json"),
        }
        argv = ["-n", "1", *[part for flag in extra for part in (flag, outputs[flag])]]
        backend = SequenceBackend(
            [[record(-60, connected=True), record(-70, bssid=BSSID_B)]]
        )
        with pytest.raises(SystemExit):
            app.run(parse(argv), backend=backend)
        out = capsys.readouterr().out
        if "--json" in extra:
            assert json.loads(out)[0]["bssid"] == BSSID_A
            return
        assert f"{BSSID_A}(*)" in out
        assert "(*): connected" in out
        assert f"{BSSID_B}(*)" not in out

    def test_exported_bssid_has_no_marker(self, tmp_path):
        path = tmp_path / "out.csv"
        backend = SequenceBackend([[record(-60, connected=True)]])
        with pytest.raises(SystemExit):
            app.run(parse(["-n", "1", "--csv", str(path)]), backend=backend)
        assert f"{BSSID_A}(*)" not in path.read_text()
        assert BSSID_A in path.read_text()


def test_interrupt_before_the_first_scan_reports_nothing(capsys, caplog):
    scanner = app.lswifi()
    scanner.report_interrupted_scans(parse(["--rssi-stats"]))
    assert "RSSI stats" not in capsys.readouterr().out
    assert "not seen" not in caplog.text
