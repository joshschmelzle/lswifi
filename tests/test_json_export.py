import json
import re
import sys

import pytest

from lswifi import __main__ as lswifi_main
from lswifi import app
from lswifi.__version__ import __version__
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from tests.test_backends import ARUBA, Session, parse


def test_two_scans_keep_scan_data_flat(tmp_path):
    path = tmp_path / "scans.json"
    args = parse(["-all", "--json", str(path)])
    record = BssRecord(**ARUBA, connected=True, ie_source="beacon")
    scanner = app.lswifi()
    first = "2026-01-01T00:00:00.000+00:00"
    second = "2026-01-01T00:01:00.000+00:00"

    for timestamp in (first, second):
        session = Session([WirelessNetworkBss(record)])
        session.last_scan_time_iso = timestamp
        scanner.parse_bss_list(session, False, "", str(path), args)

    document = json.loads(path.read_text())
    assert document["lswifi"] == {"version": f"lswifi {__version__}"}
    scan_data = document["scan_data"]
    assert [type(row) for row in scan_data] == [dict, dict]
    assert [row["timestamp"] for row in scan_data] == [first, second]
    assert [row["bssid"] for row in scan_data] == [
        "98:8f:00:9a:a4:80",
        "98:8f:00:9a:a4:80",
    ]


def test_json_append_flattens_legacy_nesting_and_truncates(tmp_path):
    path = tmp_path / "scans.json"
    legacy = {
        "lswifi": {"version": "lswifi 0.3.0"},
        "scan_data": [
            [{"bssid": "aa:aa:aa:aa:aa:aa", "pad": "x" * 200} for _ in range(40)]
        ],
    }
    path.write_text(json.dumps(legacy, indent=4))
    args = parse(["-all", "--json", str(path)])
    record = BssRecord(**ARUBA, connected=True, ie_source="beacon")
    session = Session([WirelessNetworkBss(record)])
    app.lswifi().parse_bss_list(session, False, "", str(path), args)

    text = path.read_text()
    document = json.loads(text)
    assert text == json.dumps(document, indent=args.json_indent)
    scan_data = document["scan_data"]
    assert len(scan_data) == 41
    assert all(isinstance(row, dict) for row in scan_data)
    assert scan_data[0]["bssid"] == "aa:aa:aa:aa:aa:aa"
    assert scan_data[-1]["bssid"] == "98:8f:00:9a:a4:80"


def test_uptime_sorts_by_elapsed_time_and_keeps_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("lswifi.helpers.uptime_available", lambda: True)
    records = []
    for days, hour, last in (
        (2, 10, "02"),
        (2, 2, "03"),
        (20, 1, "14"),
        (100, 1, "64"),
    ):
        records.append(
            BssRecord(
                **{
                    **ARUBA,
                    "bssid": f"02:00:00:00:00:{last}",
                    "tsf": (days * 86400 + hour * 3600) * 1_000_000,
                    "rssi_dbm": -40,
                }
            )
        )
    rows = [WirelessNetworkBss(record) for record in records]
    unknown = WirelessNetworkBss(
        BssRecord(**{**ARUBA, "bssid": "02:00:00:00:00:aa", "rssi_dbm": -40})
    )
    unknown.uptime.value = "--"
    rows.append(unknown)
    path = tmp_path / "uptime.json"
    args = parse(["-all", "--uptime", "--json", str(path)])
    out, *_rest, json_out, _new = app.lswifi().parse_bss_list(
        Session(rows), False, "", str(path), args
    )
    expected = [
        "02d 2:00:00",
        "02d 10:00:00",
        "20d 1:00:00",
        "100d 1:00:00",
        "--",
    ]
    assert [row["uptime"] for row in json_out] == expected
    assert [row[12].value for row in out] == expected
    assert [col.header.value for col in out[0]][-1] == "AP UPTIME"


def test_uptime_hidden_off_windows(tmp_path, monkeypatch):
    monkeypatch.setattr("lswifi.helpers.uptime_available", lambda: False)
    short = WirelessNetworkBss(
        BssRecord(
            **{
                **ARUBA,
                "bssid": "02:00:00:00:00:01",
                "rssi_dbm": -80,
                "tsf": 2 * 86400 * 1_000_000,
            }
        )
    )
    long = WirelessNetworkBss(
        BssRecord(
            **{
                **ARUBA,
                "bssid": "02:00:00:00:00:02",
                "rssi_dbm": -40,
                "tsf": 100 * 86400 * 1_000_000,
            }
        )
    )
    json_path = tmp_path / "uptime.json"
    csv_path = tmp_path / "uptime.csv"
    args = parse(
        [
            "-all",
            "--json",
            str(json_path),
            "--csv",
            str(csv_path),
        ]
    )
    scanner = app.lswifi()
    out, *_rest, json_out, _new = scanner.parse_bss_list(
        Session([short, long]), False, str(csv_path), str(json_path), args
    )
    assert [col.header.value for col in out[0] if "UPTIME" in col.header.value] == []
    assert [row["uptime"] for row in json_out] == [None, None]
    assert [row["bssid"] for row in json_out] == [
        "02:00:00:00:00:02",
        "02:00:00:00:00:01",
    ]
    assert [row[1].value for row in out] == [
        "02:00:00:00:00:02",
        "02:00:00:00:00:01",
    ]
    document = json.loads(json_path.read_text())
    assert document["scan_data"][0]["uptime"] is None
    header = csv_path.read_text().splitlines()[0]
    assert "uptime" not in header.split(",")
    assert args.uptime is False


def test_json_rates_are_empty_when_unadvertised(tmp_path):
    record = BssRecord(
        ssid=b"x",
        bssid="02:00:00:00:00:03",
        frequency_mhz=2412,
        ies=bytes([0, 1, ord("x")]),
    )
    path = tmp_path / "rates.json"
    args = parse(["-all", "--json", str(path)])
    _out, *_rest, json_out, _new = app.lswifi().parse_bss_list(
        Session([WirelessNetworkBss(record)]), False, "", str(path), args
    )
    assert json_out[0]["rates_basic"] == []
    assert json_out[0]["rates_data"] == []
    assert json_out[0]["rssi"] == "--"


def test_export_width_20_excludes_320(tmp_path, caplog):
    import logging

    narrow = WirelessNetworkBss(BssRecord(**ARUBA))
    wide = WirelessNetworkBss(BssRecord(**{**ARUBA, "bssid": "02:00:00:00:00:20"}))
    narrow.channel_width.value = 20
    wide.channel_width.value = 320
    path = tmp_path / "out.pcapng"
    args = parse(
        ["-all", "-export", "all", "-path", str(path), "--channel-width", "20"]
    )
    session = Session([narrow, wide])
    session.iface = type("Iface", (), {"description": "Fake Adapter"})()
    session.last_scan_time_epoch = 1_700_000_000.0
    caplog.set_level(logging.INFO)
    app.lswifi().parse_bss_list(session, False, "", "", args)
    assert "Exported 1 networks" in caplog.text


def test_export_width_skips_80_plus_80(tmp_path, caplog):
    import logging

    bss = WirelessNetworkBss(BssRecord(**ARUBA))
    bss.channel_width.value = "80+80"
    caplog.set_level(logging.INFO)
    for width in ("80", "160"):
        path = tmp_path / f"{width}.pcapng"
        args = parse(
            ["-all", "-export", "all", "-path", str(path), "--channel-width", width]
        )
        session = Session([bss])
        session.iface = type("Iface", (), {"description": "Fake Adapter"})()
        session.last_scan_time_epoch = 1_700_000_000.0
        app.lswifi().parse_bss_list(session, False, "", "", args)
        assert not path.exists()
    assert "Exported" not in caplog.text
    assert "Error exporting" not in caplog.text


def _raw_export(tmp_path, monkeypatch, argv):
    monkeypatch.setattr(app, "app_data_dir", lambda: str(tmp_path / "appdata"))
    record = BssRecord(
        ssid=b"ExampleNet", bssid="02:00:00:00:00:21", frequency_mhz=5180, ies=b""
    )
    session = Session([WirelessNetworkBss(record)])
    app.lswifi().parse_bss_list(session, False, "", "", parse(argv))
    return sorted(
        p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()
    )


def test_exportraw_writes_to_path(tmp_path, monkeypatch):
    files = _raw_export(
        tmp_path, monkeypatch, ["-exportraw", "all", "-path", str(tmp_path / "raw")]
    )
    assert files == ["raw/02-00-00-00-00-21.bss", "raw/02-00-00-00-00-21.ies"]


def test_exportraw_uses_the_directory_of_a_pcapng_path(tmp_path, monkeypatch):
    files = _raw_export(
        tmp_path,
        monkeypatch,
        ["-exportraw", "all", "-path", str(tmp_path / "out" / "scan.pcapng")],
    )
    assert files == ["out/02-00-00-00-00-21.bss", "out/02-00-00-00-00-21.ies"]


def test_exportraw_defaults_to_app_data(tmp_path, monkeypatch):
    files = _raw_export(tmp_path, monkeypatch, ["-exportraw", "all"])
    shape = r"appdata/\d{4}-\d{2}-\d{2}/\d{6}/02-00-00-00-00-21\.(bss|ies)"
    assert len(files) == 2
    assert all(re.fullmatch(shape, name) for name in files)
    assert files[0].rsplit("/", 1)[0] == files[1].rsplit("/", 1)[0]


def test_exportraw_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    files = _raw_export(tmp_path, monkeypatch, ["-exportraw", "all", "-path", "raw"])
    assert files == ["raw/02-00-00-00-00-21.bss", "raw/02-00-00-00-00-21.ies"]


def test_exportraw_rejects_a_file_path(tmp_path, monkeypatch, capsys):
    target = tmp_path / "notes.txt"
    target.write_text("x")
    monkeypatch.setattr(
        sys, "argv", ["lswifi", "-exportraw", "all", "-path", str(target)]
    )
    with pytest.raises(SystemExit) as exited:
        lswifi_main.main()
    assert exited.value.code == 2
    assert "-exportraw needs a directory" in capsys.readouterr().err


def test_exportraw_rejects_a_path_it_cannot_create(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "blocker.pcapng"
    blocker.write_text("x")
    target = blocker / "raw"
    monkeypatch.setattr(
        sys, "argv", ["lswifi", "-exportraw", "all", "-path", str(target)]
    )
    with pytest.raises(SystemExit) as exited:
        lswifi_main.main()
    assert exited.value.code == 2
    assert f"-path {target}:" in capsys.readouterr().err


def _two_bss_export(tmp_path, argv):
    records = [
        BssRecord(ssid=b"ExampleNet", bssid=bssid, frequency_mhz=5180, ies=b"")
        for bssid in ("02:00:00:00:00:21", "02:00:00:00:00:22")
    ]
    session = Session([WirelessNetworkBss(record) for record in records])
    app.lswifi().parse_bss_list(
        session, False, "", "", parse([*argv, "-path", str(tmp_path)])
    )
    return sorted(p.name for p in tmp_path.iterdir())


def test_exportraw_all_reports_once(tmp_path, capsys):
    files = _two_bss_export(tmp_path, ["-exportraw", "all"])
    assert files == [
        "02-00-00-00-00-21.bss",
        "02-00-00-00-00-21.ies",
        "02-00-00-00-00-22.bss",
        "02-00-00-00-00-22.ies",
    ]
    out = capsys.readouterr().out
    assert out.splitlines() == [f"Files exported to {tmp_path}"]


def test_exportraw_one_bssid_reports_once(tmp_path, capsys):
    files = _two_bss_export(tmp_path, ["-exportraw", "02:00:00:00:00:22"])
    assert files == ["02-00-00-00-00-22.bss", "02-00-00-00-00-22.ies"]
    out = capsys.readouterr().out
    assert out.splitlines() == [
        f"Raw byte files for 02:00:00:00:00:22 exported to {tmp_path}"
    ]


def test_exportraw_missing_bssid_reports_once(tmp_path, capsys):
    files = _two_bss_export(tmp_path, ["-exportraw", "02:00:00:00:00:99"])
    assert files == []
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "No match for 02:00:00:00:00:99 found in scan results. Please try again ..."
    ]


def test_json_security_nonconformant_only_on_flagged_6ghz(tmp_path):
    records = [
        BssRecord(
            ssid=b"x",
            bssid="02:00:00:00:00:61",
            frequency_mhz=5975,
            capability=0x0001,
            ies=bytes([0, 1, ord("x")]),
        ),
        BssRecord(
            ssid=b"x",
            bssid="02:00:00:00:00:62",
            frequency_mhz=2412,
            capability=0x0001,
            ies=bytes([0, 1, ord("x")]),
        ),
    ]
    path = tmp_path / "nonconformant.json"
    args = parse(["-all", "--json", str(path)])
    _out, *_rest, json_out, _new = app.lswifi().parse_bss_list(
        Session([WirelessNetworkBss(r) for r in records]), False, "", str(path), args
    )
    rows = {row["bssid"]: row for row in json_out}
    assert rows["02:00:00:00:00:61"]["security_nonconformant"] == ["6ghz-open"]
    assert "security_nonconformant" not in rows["02:00:00:00:00:62"]
