import json

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


def test_uptime_sorts_by_elapsed_time_and_keeps_unknown(tmp_path):
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
    assert [row[11].value for row in out] == expected


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
