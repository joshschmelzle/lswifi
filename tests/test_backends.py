# -*- encoding: utf-8

"""Fixture-based tests for the backend split (issue #99). No Wi-Fi NIC needed."""

import asyncio
import ctypes
import json
import subprocess
import sys
from pathlib import Path

import pytest

from lswifi import app, appsetup, helpers
from lswifi.backends.base import (
    BackendNotImplementedError,
    BackendUnavailableError,
    BssRecord,
    InterfaceInfo,
    RecordScanSession,
)
from lswifi.backends.factory import (
    backend_name_for_platform,
    get_backend,
    needs_backend,
)
from lswifi.elements import WirelessNetworkBss
from lswifi.schemas.bssid import BSSID
from lswifi.schemas.capabilities import Capabilities
from lswifi.schemas.channel import ChannelNumber
from lswifi.schemas.rates import Rates, get_rateset_from_ies

TESTS = Path(__file__).parent
ROOT = TESTS.parent
IES = TESTS / "ies"

# first beacon of tests/caps/wifi7aruba755-10.7.2.0.pcapng
ARUBA = dict(
    ssid=b"Wi-Fi 7",
    bssid="98:8f:00:9a:a4:80",
    frequency_mhz=2412,
    rssi_dbm=-57,
    capability=0x0451,
    beacon_interval_tu=100,
    tsf=212480058,
    ies=(IES / "wifi7-aruba-2g-rnr.ies").read_bytes(),
)

# first beacon of tests/caps/wifi7unifi.pcapng
UNIFI = dict(
    ssid=b"",
    bssid="9a:2a:6f:42:d4:7a",
    frequency_mhz=5240,
    rssi_dbm=-61,
    capability=0x1111,
    beacon_interval_tu=100,
    tsf=6759500493484,
    ies=(IES / "wifi7-unifi-5g-rnr.ies").read_bytes(),
)

# WLAN_RATE_SET: 1, 2, 5.5, 11 basic; 6-54 supported
WINDOWS_RATE_SET = [0x8002, 0x8004, 0x800B, 0x8016, 12, 18, 24, 36, 48, 72, 96, 108]

JSON_KEYS = {
    "timestamp",
    "interface_mac",
    "amendments",
    "apname",
    "bssid",
    "bss_type",
    "channel_frequency",
    "channel_number",
    "channel_width",
    "connected",
    "country_code",
    "ies",
    "ies_extension",
    "modes",
    "pmf",
    "phy_type",
    "rates_basic",
    "rates_data",
    "rssi",
    "security",
    "security_generation",
    "spatial_streams",
    "ssid",
    "stations",
    "uptime",
    "utilization",
}


def parse(argv):
    return appsetup.setup_parser().parse_args(argv)


class Session:
    """Minimal stand-in for what parse_bss_list reads from a scan session"""

    def __init__(self, data):
        self.data = data
        self.mac = "00:11:22:33:44:55"
        self.last_scan_time_iso = "2026-01-01T00:00:00"


def json_rows(records, tmp_path, extra=()):
    args = parse(["--json", str(tmp_path / "out.json"), *extra])
    data = [WirelessNetworkBss(r) for r in records]
    _out, _rnr, _len, _bssids, _names, json_out, _new = app.lswifi().parse_bss_list(
        Session(data), False, "", args.json, args
    )
    return json_out


def make_wlan_bss_entry(keep, **fields):
    """Lay out a WLAN_BSS_ENTRY followed by its IE blob, like WlanGetNetworkBssList"""
    from lswifi import wlanapi as WLAN_API

    ies = fields["ies"]
    size = ctypes.sizeof(WLAN_API.WLANBSSEntry)
    buf = ctypes.create_string_buffer(size + len(ies))
    keep.append(buf)
    entry = WLAN_API.WLANBSSEntry.from_buffer(buf)
    ssid = fields.get("ssid", b"")
    entry.dot11Ssid.SSIDLength = len(ssid)
    entry.dot11Ssid.SSID = ssid
    for i, octet in enumerate(bytes.fromhex(fields["bssid"].replace(":", ""))):
        entry.dot11Bssid[i] = octet
    entry.PhyId = 1
    entry.dot11BssType = 1
    entry.dot11BssPhyType = fields.get("phy", 10)
    entry.Rssi = fields["rssi_dbm"]
    entry.LinkQuality = 80
    entry.InRegDomain = True
    entry.BeaconPeriod = fields["beacon_interval_tu"]
    entry.Timestamp = fields["tsf"]
    entry.HostTimestamp = 133000000000000000
    entry.CapabilityInformation = fields["capability"]
    entry.ChCenterFrequency = fields["frequency_mhz"] * 1000
    rate_set = fields.get("rate_set", WINDOWS_RATE_SET)
    entry.WlanRateSet.RateSetLength = len(rate_set)
    for i, rate in enumerate(rate_set):
        entry.WlanRateSet.RateSet[i] = rate
    entry.IeOffset = size
    entry.IeSize = len(ies)
    ctypes.memmove(ctypes.addressof(buf) + size, ies, len(ies))
    return entry


class TestWindowsMapper:
    """WLANBSSEntry -> BssRecord. Builds the struct in memory, so it runs anywhere."""

    def test_maps_fields(self):
        from lswifi.backends.windows import bss_entry_to_record

        keep: list = []
        entry = make_wlan_bss_entry(keep, **ARUBA)
        record = bss_entry_to_record(entry, connected_bssid="98:8f:00:9a:a4:80")

        assert record.ssid == b"Wi-Fi 7"
        assert record.bssid == "98:8f:00:9a:a4:80"
        assert record.frequency_mhz == 2412
        assert record.rssi_dbm == -57
        assert record.link_quality == 80
        assert record.beacon_interval_tu == 100
        assert record.tsf == 212480058
        assert record.host_timestamp == 133000000000000000
        assert record.capability == 0x0451
        assert record.ies == ARUBA["ies"]
        assert record.phy_name == "HE (802.11ax)"
        assert record.bss_type == "Infrastructure"
        assert record.rate_set == WINDOWS_RATE_SET
        assert record.connected is True
        assert record.ie_source is None
        assert record.phy_id == 1
        assert record.in_reg_domain is True
        assert record.raw == bytes(entry)

    def test_not_connected_and_no_ies(self):
        from lswifi.backends.windows import bss_entry_to_record

        keep: list = []
        entry = make_wlan_bss_entry(keep, **ARUBA)
        record = bss_entry_to_record(entry, None, include_ies=False)
        assert record.connected is False
        assert record.ies == b""

    def test_empty_rate_set_stays_empty(self):
        """Windows reported an empty rate set: keep it, do not fall back to IEs."""
        from lswifi.backends.windows import bss_entry_to_record

        keep: list = []
        entry = make_wlan_bss_entry(keep, **{**ARUBA, "rate_set": []})
        record = bss_entry_to_record(entry)
        assert record.rate_set == []
        bss = WirelessNetworkBss(record)
        assert bss.wlanrateset.basic == ""
        assert bss.wlanrateset.data == ""

    def test_windows_columns(self, tmp_path, monkeypatch):
        """Columns for a WLAN_BSS_ENTRY match what main printed for the same bytes."""
        from lswifi.backends.windows import bss_entry_to_record

        monkeypatch.chdir(tmp_path)
        keep: list = []
        entry = make_wlan_bss_entry(keep, **ARUBA)
        record = bss_entry_to_record(entry, connected_bssid="98:8f:00:9a:a4:80")
        (row,) = json_rows([record], tmp_path)
        assert set(row) == JSON_KEYS
        assert row["ssid"] == "Wi-Fi 7"
        assert row["bssid"] == "98:8f:00:9a:a4:80"
        assert row["connected"] is True
        assert row["rssi"] == "-57"
        assert row["phy_type"] == "be"
        assert row["bss_type"] == "Infrastructure"
        assert row["channel_number"] == "1"
        assert row["channel_frequency"] == "2.412"
        assert row["channel_width"] == "20"
        assert row["security"] == "PSK,SAE/CCMP-128/CCMP-128"
        assert row["security_generation"] == "WPA2/3"
        assert row["pmf"] == "Capable"
        assert row["modes"] == ["ax", "be", "g", "n"]
        assert row["rates_basic"] == ["1", "2", "5.5", "11"]
        assert row["rates_data"] == ["6", "9", "12", "18", "24", "36", "48", "54"]
        if helpers.uptime_available():
            assert row["uptime"] == "00d 0:03:32"
        else:
            assert row["uptime"] is None


class TestFactory:
    @pytest.mark.parametrize(
        "platform, name",
        [
            ("win32", "windows"),
            ("linux", "linux"),
            ("darwin", "darwin"),
            ("sunos5", None),
        ],
    )
    def test_backend_name(self, platform, name):
        assert backend_name_for_platform(platform) == name

    def test_linux_without_nl80211(self, monkeypatch):
        import errno

        from lswifi.backends import nl80211

        def no_family(*args, **kwargs):
            raise OSError(errno.ENOENT, "nl80211 not found")

        monkeypatch.setattr(nl80211, "GenericNetlink", no_family)
        with pytest.raises(BackendUnavailableError, match="nl80211"):
            get_backend("linux")

    def test_unknown_platform(self):
        with pytest.raises(BackendNotImplementedError, match="sunos5"):
            get_backend("sunos5")

    def test_darwin_without_pyobjc(self, monkeypatch):
        # a None entry makes "import CoreWLAN" raise ImportError on any OS
        monkeypatch.setitem(sys.modules, "CoreWLAN", None)
        with pytest.raises(BackendUnavailableError, match="pyobjc-framework-CoreWLAN"):
            get_backend("darwin")

    def test_windows_without_wlanapi(self, monkeypatch):
        from lswifi import wlanapi as WLAN_API

        monkeypatch.setattr(WLAN_API, "WLAN_API_EXISTS", False)
        with pytest.raises(BackendUnavailableError, match="wlanapi.dll"):
            get_backend("win32")

    @pytest.mark.parametrize(
        "argv, expected",
        [
            ([], True),
            (["-decode", "x.pcapng"], False),
            (["-decoderaw", "x.ies"], False),
            (["--data-location"], False),
            (["--list-interfaces"], True),
            (["-ap"], True),
            (["--watchevents"], True),
        ],
    )
    def test_needs_backend(self, argv, expected):
        assert needs_backend(parse(argv)) is expected


def run_lswifi(*argv, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-m", "lswifi", *argv],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


class TestRawIes:
    def test_decode_bytefile_ies_without_wlanapi(self):
        """Decode a raw .ies fixture in a fresh interpreter and check that
        lswifi.wlanapi is never imported."""
        code = (
            "import sys\n"
            "from lswifi.elements import WirelessNetworkBss\n"
            f"data = open({str(IES / 'wifi7-aruba-2g-rnr.ies')!r}, 'rb').read()\n"
            "ies = WirelessNetworkBss.decode_bytefile_ies(bytearray(data))\n"
            "print('|'.join(str(ie.eid) + '=' + ie.name for ie in ies if ie.eid != ''))\n"
            "print('wlanapi' if 'lswifi.wlanapi' in sys.modules else 'no-wlanapi')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT
        )
        assert result.returncode == 0, result.stderr
        names, marker = result.stdout.strip().splitlines()
        assert marker == "no-wlanapi"
        assert "0=SSID" in names
        assert "1=Supported Rates" in names
        assert "201=Reduced Neighbor Report" in names

    def test_rnr_decoded_from_raw_ies(self):
        data = (IES / "wifi7-unifi-5g-rnr.ies").read_bytes()
        ies = WirelessNetworkBss.decode_bytefile_ies(bytearray(data))
        rnr = [ie for ie in ies if ie.eid == 201]
        assert rnr
        assert "TBTT" in "\n".join(ie.decoded for ie in ies)

    def test_process_information_elements_from_record(self):
        bss = WirelessNetworkBss(BssRecord(**ARUBA))
        eids = [ie.eid for ie in bss.information_elements if ie.eid != ""]
        assert eids[:3] == [0, 1, 3]
        assert 201 in eids
        assert bss.has_rnr
        assert bss.ie_size == len(ARUBA["ies"])

    def test_empty_ies(self):
        bss = WirelessNetworkBss(BssRecord(**{**ARUBA, "ies": b""}))
        assert bss.information_elements == []

    @pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows CLI")
    def test_cli_decoderaw_ies(self):
        result = run_lswifi("-decoderaw", str(IES / "mikrotik-2g-ext-rates.ies"))
        assert result.returncode == 0, result.stderr
        assert "Decoded Information Elements:" in result.stdout
        assert "Extended Supported Rates" in result.stdout

    @pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows CLI")
    def test_cli_decoderaw_bss_fails_cleanly(self, tmp_path):
        bss_file = tmp_path / "98-8f-00-9a-a4-80.bss"
        bss_file.write_bytes(b"\x00" * 64)
        result = run_lswifi("-decoderaw", str(bss_file))
        assert result.returncode != 0
        assert "Traceback" not in result.stderr
        assert "requires Windows" in result.stdout + result.stderr


class TestRatesFallback:
    def test_from_ies_supported_and_extended(self):
        data = (IES / "mikrotik-2g-ext-rates.ies").read_bytes()
        rates = Rates.from_ies(data)
        # IE 1: 82 84 8B 96 0C 12 18 24, IE 50: 30 48 60 6C
        assert rates.basic == "1 2 5.5 11"
        assert rates.data == "6 9 12 18 24 36 48 54"

    def test_selectors_are_skipped(self):
        # Supported Rates: 6(B) 9 12(B) + basic SAE-H2E (123) and HT PHY (127)
        ies = bytes([1, 5, 0x8C, 0x12, 0x98, 0x80 | 123, 0x80 | 127])
        assert get_rateset_from_ies(ies) == [0x800C, 0x12, 0x8018]

    def test_truncated_element_is_ignored(self):
        ies = bytes([1, 2, 0x82, 0x84, 50, 4, 0x0C])
        assert get_rateset_from_ies(ies) == [0x8002, 0x8004]

    def test_record_without_rate_set_uses_ies(self):
        # IE 1: 98 24 B0 48 60 6C
        bss = WirelessNetworkBss(BssRecord(**ARUBA))
        assert bss.wlanrateset.basic == "12 24"
        assert bss.wlanrateset.data == "18 36 48 54"


class TestPlainSchemas:
    def test_channel_number(self):
        assert ChannelNumber(2412).value == "1"
        assert ChannelNumber(5240).value == "48"
        assert ChannelNumber(5955).value == "1"

    def test_bssid(self):
        bssid = BSSID("98:8f:00:9a:a4:80", True, header="BSSID")
        assert bssid.value == "98:8f:00:9a:a4:80"
        assert bssid.connected is True
        assert BSSID("98:8f:00:9a:a4:80").connected is False

    def test_capabilities(self):
        caps = Capabilities(0x0451)
        assert caps.hex == "0x451"
        assert caps.ess == 1
        assert caps.privacy == 1
        assert caps.short_slot_time == 1
        assert caps.ibss == 0


class FakeBackend:
    """In-memory backend that satisfies WifiBackend"""

    name = "fake"
    supports_events = False

    def __init__(self, records):
        self.records = records
        self.iface = InterfaceInfo(
            connection_name="Wi-Fi",
            description="Fake Adapter",
            guid_string="{00000000-0000-0000-0000-000000000000}",
            mac="02:00:00:00:00:01",
            state_string="connected",
        )

    def list_interfaces(self):
        return [self.iface]

    def scan(self, iface):
        return list(self.records)

    def open_session(self, args, iface):
        return RecordScanSession(self, iface, args)

    def interface_info(self, args, iface):
        return f"INTERFACE: {iface.connection_name}"


def fake_records():
    return [
        BssRecord(**ARUBA, connected=True, ie_source="beacon"),
        BssRecord(**UNIFI, ie_source="beacon"),
    ]


class TestFakeBackend:
    def test_parse_bss_list_keys(self, tmp_path, monkeypatch):
        """A non-Windows record (no PHY enum, no rate set) yields the same JSON keys."""
        monkeypatch.chdir(tmp_path)
        rows = json_rows(fake_records(), tmp_path, extra=["-all"])
        assert len(rows) == 2
        for row in rows:
            assert set(row) == JSON_KEYS
        aruba, unifi = rows
        assert aruba["ssid"] == "Wi-Fi 7"
        assert aruba["connected"] is True
        assert aruba["channel_frequency"] == "2.412"
        assert aruba["phy_type"] == "be"  # from the EHT IEs, not an OS enum
        assert "be" in aruba["modes"]
        assert aruba["rates_basic"] == ["12", "24"]  # from the rates IEs
        assert aruba["rates_data"] == ["18", "36", "48", "54"]
        assert unifi["channel_frequency"] == "5.240"
        assert unifi["channel_number"] == "48"
        assert unifi["connected"] is False

    def test_scan_session(self):
        backend = FakeBackend(fake_records())
        args = parse([])
        session = backend.open_session(args, backend.list_interfaces()[0])
        asyncio.run(session.scan())
        assert session.scan_finished
        assert [str(b.bssid) for b in session.data] == [
            "98:8f:00:9a:a4:80",
            "9a:2a:6f:42:d4:7a",
        ]
        assert session.last_scan_time_iso

    def test_one_bad_bss_does_not_drop_the_scan(self, monkeypatch):
        from lswifi import elements

        good = BssRecord(**ARUBA, ie_source="beacon")
        bad = BssRecord(**{**UNIFI, "bssid": "02:00:00:00:00:ff"}, ie_source="beacon")
        real = elements.WirelessNetworkBss

        class Boom(real):
            def __init__(self, bss, *args, **kwargs):
                if str(bss.bssid).endswith("ff"):
                    raise ValueError("bad ie")
                super().__init__(bss, *args, **kwargs)

        monkeypatch.setattr(elements, "WirelessNetworkBss", Boom)
        backend = FakeBackend([good, bad])
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        asyncio.run(session.scan())
        assert session.scan_finished
        assert [str(b.bssid) for b in session.data] == ["98:8f:00:9a:a4:80"]

    def test_windows_bss_list_skips_bad_record(self, monkeypatch):
        from lswifi import elements, wlanapi

        good = BssRecord(**ARUBA, ie_source="beacon")
        bad = BssRecord(**{**UNIFI, "bssid": "02:00:00:00:00:ff"}, ie_source="beacon")
        real = elements.WirelessNetworkBss

        class Boom(real):
            def __init__(self, bss, *args, **kwargs):
                if str(bss.bssid).endswith("ff"):
                    raise ValueError("bad ie")
                super().__init__(bss, *args, **kwargs)

        monkeypatch.setattr(wlanapi, "WirelessNetworkBss", Boom)
        monkeypatch.setattr(
            wlanapi.WLAN,
            "get_wireless_network_bss_records",
            staticmethod(lambda interface: [good, bad]),
        )
        parsed = wlanapi.WLAN.get_wireless_network_bss_list(object(), False)
        assert [str(bss.bssid) for bss in parsed] == ["98:8f:00:9a:a4:80"]

    def test_lswifi_scan(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        backend = FakeBackend(fake_records())
        args = parse(["-all", "--json", str(tmp_path / "out.json")])
        clients = {0: backend.open_session(args, backend.list_interfaces()[0])}
        asyncio.run(app.lswifi().scan(clients, False, "", args.json, args))
        printed = [l for l in capsys.readouterr().out.splitlines() if l.startswith("[")]
        rows = json.loads(printed[-1])
        assert [r["bssid"] for r in rows] == ["98:8f:00:9a:a4:80", "9a:2a:6f:42:d4:7a"]
        assert rows[0]["interface_mac"] == "02:00:00:00:00:01"

    def test_run_table(self, capsys):
        backend = FakeBackend(fake_records())
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["-all"]), backend=backend)
        assert exited.value.code == 0
        out = capsys.readouterr().out
        assert "Wi-Fi 7" in out
        assert "98:8f:00:9a:a4:80(*)" in out
        assert "9a:2a:6f:42:d4:7a" in out

    def test_run_list_interfaces(self, capsys):
        backend = FakeBackend([])
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["--list-interfaces"]), backend=backend)
        assert exited.value.code == 0
        out = capsys.readouterr().out
        assert "Connection Name: Wi-Fi" in out
        assert "GUID: 00000000-0000-0000-0000-000000000000" in out
        assert "MAC: 02:00:00:00:00:01" in out

    def test_run_interface_info(self, capsys):
        backend = FakeBackend([])
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["-ap"]), backend=backend)
        assert exited.value.code == 0
        assert "INTERFACE: Wi-Fi" in capsys.readouterr().out

    def test_run_watchevents_unsupported(self, caplog):
        backend = FakeBackend([])
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["--watchevents"]), backend=backend)
        assert exited.value.code == -1
        assert "--watchevents is unsupported on fake" in caplog.text

    def test_run_without_interfaces_exits_nonzero(self, caplog):
        backend = FakeBackend([])
        backend.list_interfaces = lambda: []
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["-all"]), backend=backend)
        assert exited.value.code == -1
        assert "no wireless interfaces found" in caplog.text

    @pytest.mark.parametrize(
        "flag, name, content, message",
        [
            ("-decode", "corrupt.pcapng", b"not a capture", "Unknown file format"),
            ("-decode", "empty.pcap", b"", "Unknown file format"),
            ("-decode", "magic.pcap", b"\xd4\xc3\xb2\xa1", "header too short"),
            ("-decode", "magic.pcapng", b"\x0a\x0d\x0d\x0a", "header too short"),
            ("-decoderaw", "notes.txt", b"\x00" * 8, "needs a .ies or .bss file"),
            ("-decoderaw", "noextension", b"\x00" * 8, "needs a .ies or .bss file"),
        ],
    )
    def test_decode_bad_file_exits_nonzero(
        self, tmp_path, flag, name, content, message, caplog
    ):
        target = tmp_path / name
        target.write_bytes(content)
        with pytest.raises(SystemExit) as exited:
            app.run(parse([flag, str(target)]), backend=None)
        assert exited.value.code == -1
        assert message in caplog.text

    def test_run_interrupted_exits_nonzero(self):
        backend = FakeBackend(fake_records())

        def interrupted(*_args, **_kwargs):
            raise KeyboardInterrupt

        backend.list_interfaces = interrupted
        with pytest.raises(SystemExit) as exited:
            app.run(parse(["-all"]), backend=backend)
        assert exited.value.code == -1

    @pytest.mark.parametrize("flag", ["-decode", "-decoderaw"])
    def test_decode_missing_file_exits_nonzero(self, tmp_path, flag, capsys):
        missing = str(tmp_path / "missing.ies")
        with pytest.raises(SystemExit) as exited:
            app.run(parse([flag, missing]), backend=None)
        assert exited.value.code == -1
        assert "does not exist" in capsys.readouterr().out


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows CLI")
class TestCliOffWindows:
    def test_version(self):
        result = run_lswifi("-V")
        assert result.returncode == 0, result.stderr
        from lswifi.__version__ import __version__

        assert __version__ in result.stdout + result.stderr

    def test_help(self):
        result = run_lswifi("-h")
        assert result.returncode == 0, result.stderr
        assert "usage" in result.stdout

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="scans the host's adapters"
    )
    def test_linux_scan_runs_or_fails_cleanly(self):
        # a real scan where there is an nl80211 adapter, else a short error
        result = run_lswifi()
        assert "not implemented yet" not in result.stderr
        assert "Traceback" not in result.stderr

    def test_import_elements_does_not_exit(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import lswifi.elements, lswifi.wlanapi; print('ok')",
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"


class TestIntegerRssiParity:
    RSSI_RANGE = range(-110, 1)

    def test_sort_key_matches_plain_int_sort(self):
        values = list(reversed(self.RSSI_RANGE))
        assert [app.rssi_sort_key(v) for v in values] == values
        assert sorted(values, key=app.rssi_sort_key) == sorted(values)

    def test_export_sorts_rssi_numerically_strongest_first(self, tmp_path, monkeypatch):
        from lswifi.backends.windows import bss_entry_to_record

        monkeypatch.chdir(tmp_path)
        keep: list = []
        records = [
            bss_entry_to_record(
                make_wlan_bss_entry(
                    keep, **{**ARUBA, "bssid": f"02:00:00:00:00:0{i}", "rssi_dbm": rssi}
                )
            )
            for i, rssi in enumerate([-9, -43, -75])
        ]
        rows = json_rows(records, tmp_path)
        assert [row["rssi"] for row in rows] == ["-9", "-43", "-75"]

    @pytest.mark.parametrize("threshold", [-110, -82, -70, -1])
    def test_threshold_filter_matches_int_compare(self, tmp_path, threshold):
        records = [
            BssRecord(**{**UNIFI, "bssid": f"02:00:00:00:00:{i:02x}", "rssi_dbm": rssi})
            for i, rssi in enumerate(self.RSSI_RANGE)
        ]
        rows = json_rows(records, tmp_path, extra=["-t", str(threshold)])
        kept = sorted(int(row["rssi"]) for row in rows)
        assert kept == [r for r in self.RSSI_RANGE if r >= threshold]


@pytest.mark.skipif(
    sys.platform.startswith("linux"), reason="checks that non-Linux never loads them"
)
def test_linux_modules_not_loaded_off_linux():
    script = """
import sys
import lswifi.__main__, lswifi.app
from lswifi.backends.base import BackendError, BackendUnavailableError
from lswifi.backends.factory import get_backend

other = "darwin" if sys.platform == "win32" else "win32"
try:
    get_backend(other)
except BackendUnavailableError:
    pass
else:
    raise SystemExit(f"{other} backend loaded on {sys.platform}")
try:
    get_backend()
except BackendError:
    pass
loaded = sorted(
    name for name in sys.modules
    if name in ("lswifi.backends.linux", "lswifi.backends.linux_events", "lswifi.backends.nl80211")
)
raise SystemExit(f"loaded: {loaded}" if loaded else 0)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stdout + result.stderr
