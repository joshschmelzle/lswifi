# -*- encoding: utf-8

import json
from pathlib import Path

from lswifi import app
from lswifi.__version__ import __version__
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from tests.test_backends import ARUBA, Session, parse

SCAN_KEYS = {"lswifi", "timestamp", "scan_data"}


def export_scan(path: Path, timestamp: str) -> None:
    args = parse(["-all", "--indent", "4", "--json", str(path)])
    record = BssRecord(**ARUBA, connected=True, ie_source="beacon")
    session = Session([WirelessNetworkBss(record)])
    session.last_scan_time_iso = timestamp
    app.lswifi().parse_bss_list(session, False, "", str(path), args)


def scan_objects(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines
    assert all(line == json.dumps(json.loads(line)) for line in lines)
    return [json.loads(line) for line in lines]


class TestJsonScanFile:
    def test_two_scans_append_two_consistent_lines(self, tmp_path):
        path = tmp_path / "scans.json"
        first = "2026-01-01T00:00:00.000+00:00"
        second = "2026-01-01T00:01:00.000+00:00"

        export_scan(path, first)
        export_scan(path, second)

        scans = scan_objects(path)
        assert len(scans) == 2
        assert [scan["timestamp"] for scan in scans] == [first, second]
        for scan, timestamp in zip(scans, (first, second), strict=True):
            assert set(scan) == SCAN_KEYS
            assert scan["lswifi"] == {"version": f"lswifi {__version__}"}
            assert isinstance(scan["scan_data"], list)
            assert len(scan["scan_data"]) == 1
            bss = scan["scan_data"][0]
            assert isinstance(bss, dict)
            assert bss["bssid"] == "98:8f:00:9a:a4:80"
            assert bss["timestamp"] == timestamp
        assert set(scans[0]["scan_data"][0]) == set(scans[1]["scan_data"][0])

    def test_existing_file_is_appended_not_reread(self, tmp_path, monkeypatch):
        path = tmp_path / "scans.json"
        prior = b'{"prior": true}\n'
        path.write_bytes(prior)

        modes = []
        real_open = open

        def tracking_open(file, mode="r", *args, **kwargs):
            if Path(file) == path:
                modes.append(mode)
            return real_open(file, mode, *args, **kwargs)

        def fail_load(*_args, **_kwargs):
            raise AssertionError("json export must not read the existing file")

        monkeypatch.setattr("builtins.open", tracking_open)
        monkeypatch.setattr(app.json, "load", fail_load)

        export_scan(path, "2026-01-01T00:00:00.000+00:00")
        export_scan(path, "2026-01-01T00:01:00.000+00:00")

        raw = path.read_bytes()
        assert raw.startswith(prior)
        assert modes == ["a", "a"]
        lines = raw.decode("utf-8").splitlines()
        assert lines[0] == '{"prior": true}'
        scans = [json.loads(line) for line in lines[1:]]
        assert len(scans) == 2
        assert all(set(scan) == SCAN_KEYS for scan in scans)
        assert all(isinstance(scan["scan_data"][0], dict) for scan in scans)
