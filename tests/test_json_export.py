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
