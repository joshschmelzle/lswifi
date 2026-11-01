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
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from tests.test_backends import FakeBackend, Session, parse

IFACE_MAC = "00:00:5e:00:53:aa"
BSSID_A = "00:00:5e:00:53:01"
BSSID_B = "00:00:5e:00:53:02"
SSID = b"ExampleNet"


def record(rssi_dbm, bssid=BSSID_A, connected=False):
    return BssRecord(
        ssid=SSID,
        bssid=bssid,
        frequency_mhz=5180,
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


def stats_args(*extra):
    return parse(["-bssid", BSSID_A, "-all", "--rssi-stats", "-i", "0", *extra])


class TestRssiStatsUnit:
    def test_summarize_three_samples(self):
        samples = {
            (IFACE_MAC, BSSID_A): [
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
        samples = {(IFACE_MAC, BSSID_A): [("2026-01-01T00:00:00", -60)]}
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
        assert "stdev" not in rssistats.format_summary(summaries[0])

    def test_summarize_sorts_by_interface_mac_then_bssid(self):
        samples = {
            ("00:00:5e:00:53:bb", BSSID_A): [("t1", -60)],
            (IFACE_MAC, BSSID_B): [("t2", -62)],
            (IFACE_MAC, BSSID_A): [("t3", -64)],
        }
        summaries = rssistats.summarize(samples, 1)
        assert [(s.interface_mac, s.bssid) for s in summaries] == [
            (IFACE_MAC, BSSID_A),
            (IFACE_MAC, BSSID_B),
            ("00:00:5e:00:53:bb", BSSID_A),
        ]

    def test_add_sample_with_none_rssi_is_ignored(self):
        samples = {}
        rssistats.add_sample(samples, IFACE_MAC, BSSID_A, "t1", None)
        assert samples == {}

    def test_summary_to_json_key_set_and_types(self):
        summary = rssistats.RssiSummary(
            interface_mac=IFACE_MAC,
            bssid=BSSID_A,
            first_timestamp="2026-01-01T00:00:00",
            last_timestamp="2026-01-01T00:00:01",
            completed_scans=2,
            samples=2,
            mean_dbm=-61.0,
            stdev_db=1.0,
            min_dbm=-62,
            max_dbm=-60,
            spread_db=2,
        )
        obj = rssistats.summary_to_json(summary)
        assert set(obj) == {
            "interface_mac",
            "bssid",
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
        assert isinstance(obj["interface_mac"], str)
        assert isinstance(obj["bssid"], str)
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
            IFACE_MAC, BSSID_A, "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
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
            IFACE_MAC, BSSID_A, "t1", "t2", 2, 2, -61.0, 1.0, -62, -60, 2
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
            IFACE_MAC, BSSID_A, "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
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
            IFACE_MAC, BSSID_A, "t1", "t1", 1, 1, -60.0, None, -60, -60, 0
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
        assert (IFACE_MAC, BSSID_A) in scanner.rssi_samples
        assert (IFACE_MAC, f"{BSSID_A}(*)") not in scanner.rssi_samples

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

    def test_partial_bssid_match_creates_two_groups(self):
        scanner = app.lswifi()
        args = parse(["-bssid", "00:00:5e:00:53", "-all", "--rssi-stats"])
        records = [
            record(-60, bssid=BSSID_A),
            record(-62, bssid=BSSID_B),
        ]
        scanner.parse_bss_list(self._session(records), False, "", "", args)
        assert set(scanner.rssi_samples) == {(IFACE_MAC, BSSID_A), (IFACE_MAC, BSSID_B)}


class TestCliValidation:
    def test_rssi_stats_without_bssid(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["lswifi", "-all", "--rssi-stats"])
        with pytest.raises(SystemExit) as exited:
            lswifi_main.main()
        assert exited.value.code == 2
        assert "--rssi-stats needs -bssid" in capsys.readouterr().err

    def test_rssi_stats_without_all(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["lswifi", "-bssid", BSSID_A, "--rssi-stats"])
        with pytest.raises(SystemExit) as exited:
            lswifi_main.main()
        assert exited.value.code == 2
        assert "-82 dBm threshold" in capsys.readouterr().err


class TestAppRun:
    def test_three_scans_json_summary_and_keys(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[record(-60)], [record(-62)], [record(-64)]])
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("--json", str(path), "-n", "3"),
                backend=backend,
            )
        assert exited.value.code == 0
        assert (
            f"{IFACE_MAC} {BSSID_A}: 3/3 scans, mean -62.0 dBm, stdev 2.0 dB, "
            "min -64 dBm, max -60 dBm, spread 4 dB" in caplog.text
        )

        document = json.loads(path.read_text())
        assert len(document["rssi_stats"]) == 1
        stats = document["rssi_stats"][0]
        assert set(stats) == {
            "interface_mac",
            "bssid",
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
        assert isinstance(stats["min_dbm"], int)
        assert isinstance(stats["max_dbm"], int)
        assert isinstance(stats["spread_db"], int)
        timestamps = [row["timestamp"] for row in document["scan_data"]]
        assert stats["first_timestamp"] == timestamps[0]
        assert stats["last_timestamp"] == timestamps[-1]

    def test_two_runs_into_one_file_append(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
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

    def test_missing_scan_counts_as_completed(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[record(-60)], [], [record(-64)]])
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("-n", "3", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 0
        assert "2/3 scans" in caplog.text

    def test_weak_rssi_below_default_threshold_counts(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[record(-60)], [record(-90)], [record(-62)]])
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("-n", "3", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 0
        assert "3/3 scans" in caplog.text

    def test_one_scan_no_stdev(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[record(-60)]])
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("-n", "1", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 0
        assert "mean -60.0 dBm" in caplog.text
        assert "min -60 dBm, max -60 dBm, spread 0 dB" in caplog.text
        assert "stdev" not in caplog.text

    def test_no_match_logs_warning_and_creates_no_json(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[]])
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                stats_args("--json", str(path), "-n", "1", "-i", "0"),
                backend=backend,
            )
        assert exited.value.code == 0
        assert f"no samples matched -bssid {BSSID_A}" in caplog.text
        assert not path.exists()

    def test_without_rssi_stats_no_summary_or_key(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        backend = SequenceBackend([[record(-60)]])
        path = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exited:
            app.run(
                parse(
                    [
                        "-bssid",
                        BSSID_A,
                        "-all",
                        "--json",
                        str(path),
                        "-n",
                        "1",
                        "-i",
                        "0",
                    ]
                ),
                backend=backend,
            )
        assert exited.value.code == 0
        assert "mean" not in caplog.text
        assert "rssi_stats" not in json.loads(path.read_text())


@pytest.mark.skipif(sys.platform == "win32", reason="sends SIGINT")
def test_ctrl_c_logs_summary_without_json_write(tmp_path):
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
        _, err = proc.communicate(timeout=10)
    finally:
        proc.kill()
    assert proc.returncode == 130
    assert "1/1 scans, mean -57.0 dBm, min -57 dBm, max -57 dBm, spread 0 dB" in err
    assert "Traceback" not in err
    assert "rssi_stats" not in json.loads(path.read_text())
