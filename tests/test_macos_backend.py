# -*- encoding: utf-8

"""macOS CoreWLAN backend (issue #101).

Everything except TestRealScan uses fake CoreWLAN-shaped objects, so it runs
on any OS and never imports CoreWLAN.
"""

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lswifi import app, appsetup
from lswifi.backends import macos
from lswifi.backends.base import BackendError, BssRecord
from lswifi.backends.macos import (
    MacOSBackend,
    MacOSScanSession,
    frequency_from_channel,
    network_to_record,
)
from lswifi.elements import WirelessNetworkBss

TESTS = Path(__file__).parent
ROOT = TESTS.parent
IES = TESTS / "ies"

# stands in for informationElementData: first beacon of
# tests/caps/wifi7aruba755-10.7.2.0.pcapng, IE chain only
ARUBA_IES = (IES / "wifi7-aruba-2g-rnr.ies").read_bytes()


def parse(argv):
    return appsetup.setup_parser().parse_args(argv)


class FakeChannel:
    def __init__(self, number, band, width):
        self._number, self._band, self._width = number, band, width

    def channelNumber(self):
        return self._number

    def channelBand(self):
        return self._band

    def channelWidth(self):
        return self._width


class FakeNetwork:
    """Shaped like CWNetwork; None models a location-gated nil"""

    def __init__(
        self,
        ssid=None,
        bssid=None,
        rssi=-60,
        channel=None,
        beacon=100,
        ies=None,
        ibss=False,
    ):
        self._ssid, self._bssid, self._rssi = ssid, bssid, rssi
        self._channel, self._beacon, self._ies, self._ibss = channel, beacon, ies, ibss

    def ssidData(self):
        return self._ssid

    def bssid(self):
        return self._bssid

    def rssiValue(self):
        return self._rssi

    def wlanChannel(self):
        return self._channel

    def beaconInterval(self):
        return self._beacon

    def informationElementData(self):
        return self._ies

    def ibss(self):
        return self._ibss


def granted_network(**kw):
    return FakeNetwork(
        ssid=b"Wi-Fi 7",
        bssid="98:8F:00:9A:A4:80",
        rssi=-57,
        channel=FakeChannel(1, macos.CW_CHANNEL_BAND_2GHZ, 1),
        ies=ARUBA_IES,
        **kw,
    )


def redacted_network(**kw):
    return FakeNetwork(channel=FakeChannel(149, macos.CW_CHANNEL_BAND_6GHZ, 4), **kw)


class FakeInterface:
    def __init__(self, networks=(), cached=(), error=None, bssid=None):
        self.networks, self.cached, self.error, self._bssid = networks, cached, error, bssid

    def interfaceName(self):
        return "en0"

    def hardwareAddress(self):
        return "C0:C7:DB:00:00:01"

    def powerOn(self):
        return True

    def interfaceMode(self):
        return 1

    def bssid(self):
        return self._bssid

    def ssidData(self):
        return None

    def wlanChannel(self):
        return FakeChannel(44, macos.CW_CHANNEL_BAND_5GHZ, 1)

    def rssiValue(self):
        return -44

    def noiseMeasurement(self):
        return -93

    def transmitRate(self):
        return 286.0

    def transmitPower(self):
        return 17

    def countryCode(self):
        return None

    def scanForNetworksWithSSID_error_(self, ssid, error):
        assert ssid is None  # broadcast scan, like WLAN.wlan_scan
        return (None if self.networks is None else set(self.networks)), self.error

    def cachedScanResults(self):
        return None if self.cached is None else set(self.cached)


def fake_corewlan(cw_iface):
    client = SimpleNamespace(
        interfaces=lambda: [cw_iface],
        interfaceWithName_=lambda name: cw_iface,
    )
    return SimpleNamespace(
        CWWiFiClient=SimpleNamespace(sharedWiFiClient=lambda: client)
    )


@pytest.fixture(autouse=True)
def reset_location_warning(monkeypatch):
    monkeypatch.setattr(macos, "_location_warned", False)


class TestFrequency:
    @pytest.mark.parametrize(
        "channel, band, mhz",
        [
            (1, macos.CW_CHANNEL_BAND_2GHZ, 2412),
            (14, macos.CW_CHANNEL_BAND_2GHZ, 2484),
            (36, macos.CW_CHANNEL_BAND_5GHZ, 5180),
            (165, macos.CW_CHANNEL_BAND_5GHZ, 5825),
            (1, macos.CW_CHANNEL_BAND_6GHZ, 5955),
            (37, macos.CW_CHANNEL_BAND_6GHZ, 6135),
            (233, macos.CW_CHANNEL_BAND_6GHZ, 7115),
            (6, 0, 2437),  # unknown band: 2.4/5 GHz table
            (0, None, 0),
        ],
    )
    def test_frequency(self, channel, band, mhz):
        assert frequency_from_channel(channel, band) == mhz


class TestMapper:
    def test_granted(self):
        record = network_to_record(granted_network(), connected_bssid="98:8f:00:9a:a4:80")
        assert record.ssid == b"Wi-Fi 7"
        assert record.bssid == "98:8f:00:9a:a4:80"
        assert record.frequency_mhz == 2412
        assert record.rssi_dbm == -57
        assert record.beacon_interval_tu == 100
        assert record.capability == 0
        assert record.ies == ARUBA_IES
        assert record.phy_name is None
        assert record.rate_set is None
        assert record.link_quality is None
        assert record.bss_type == "Infrastructure"
        assert record.connected is True
        assert record.ie_source is None
        assert record.channel_width_mhz == 20

    def test_redacted_is_nil_safe(self):
        record = network_to_record(redacted_network(), connected_bssid=None)
        assert record.ssid == b""
        assert record.bssid == ""
        assert record.ies == b""
        assert record.connected is False
        assert record.frequency_mhz == 6695
        assert record.rssi_dbm == -60
        assert record.channel_width_mhz == 160
        assert macos.is_redacted(record)

    def test_no_channel(self):
        record = network_to_record(FakeNetwork(channel=None, rssi=None, beacon=None))
        assert record.frequency_mhz == 0
        assert record.rssi_dbm is None
        assert record.beacon_interval_tu == 0

    def test_ibss(self):
        assert network_to_record(redacted_network(ibss=True)).bss_type == "Independent"

    def test_ie_columns_match_decode(self):
        """IE-derived columns equal decoding the same bytes directly"""
        mac = WirelessNetworkBss(network_to_record(granted_network()))
        direct = WirelessNetworkBss(
            BssRecord(ssid=b"Wi-Fi 7", bssid="98:8f:00:9a:a4:80", frequency_mhz=2412, ies=ARUBA_IES)
        )
        for attr in ("security", "pmf", "channel_width", "spatial_streams", "phy_type"):
            assert str(getattr(mac, attr)) == str(getattr(direct, attr)), attr
        assert mac.amendments.elements == direct.amendments.elements
        assert str(mac.security) == "PSK,SAE/CCMP-128/CCMP-128"
        assert mac.phy_type.amendment == "be"
        assert "be" in mac.modes  # Modes.__str__ has no "be" slot on main either
        assert str(mac.wlanrateset.basic).split() == ["12", "24"]

    def test_ie_width_wins(self):
        """CWChannel says 160 MHz; the 2.4 GHz IEs say 20"""
        network = granted_network()
        network._channel = FakeChannel(1, macos.CW_CHANNEL_BAND_2GHZ, 4)
        bss = WirelessNetworkBss(network_to_record(network))
        assert str(bss.channel_width) == "20"

    def test_channel_width_fallback_without_ies(self):
        bss = WirelessNetworkBss(network_to_record(redacted_network()))
        assert str(bss.channel_width) == "160"
        assert str(bss.channel_number_marked).strip() == "149@160"


class TestBackend:
    def test_list_interfaces(self):
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        (iface,) = backend.list_interfaces()
        assert iface.connection_name == "en0"
        assert iface.mac == "c0:c7:db:00:00:01"
        assert iface.state_string == "connected"
        assert backend.supports_events is True

    def test_scan(self):
        cw = FakeInterface(networks=[granted_network(), redacted_network()], bssid="98:8F:00:9A:A4:80")
        backend = MacOSBackend(fake_corewlan(cw))
        records = backend.scan(backend.list_interfaces()[0])
        assert sorted(r.bssid for r in records) == ["", "98:8f:00:9a:a4:80"]
        assert [r.connected for r in records if r.bssid] == [True]

    def test_scan_error_with_results(self):
        """observed on macOS 26: kCWTimeoutErr alongside a full result set"""
        cw = FakeInterface(networks=[redacted_network()], error="-3905")
        backend = MacOSBackend(fake_corewlan(cw))
        assert len(backend.scan(backend.list_interfaces()[0])) == 1

    def test_scan_falls_back_to_cache(self):
        cw = FakeInterface(networks=None, cached=[redacted_network()], error="-3905")
        backend = MacOSBackend(fake_corewlan(cw))
        assert len(backend.scan(backend.list_interfaces()[0])) == 1

    def test_scan_failure(self):
        cw = FakeInterface(networks=None, cached=None, error="-3905")
        backend = MacOSBackend(fake_corewlan(cw))
        with pytest.raises(BackendError, match="-3905"):
            backend.scan(backend.list_interfaces()[0])

    def test_cached_scan(self):
        cw = FakeInterface(networks=None, cached=[redacted_network()])
        backend = MacOSBackend(fake_corewlan(cw))
        assert len(backend.cached_scan(backend.list_interfaces()[0])) == 1

    def test_session_redacted(self, caplog):
        cw = FakeInterface(networks=[redacted_network(), redacted_network(rssi=-70)])
        backend = MacOSBackend(fake_corewlan(cw))
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        assert isinstance(session, MacOSScanSession)
        with caplog.at_level(logging.WARNING):
            asyncio.run(session.scan())
            asyncio.run(session.scan())
        warnings = [r for r in caplog.records if "Location Services" in r.getMessage()]
        assert len(warnings) == 1
        assert "sudo does not help" in caplog.text
        assert session.data is not None and len(session.data) == 2
        for bss in session.data:
            assert str(bss.security) == "--"
            assert str(bss.spatial_streams) == "--"
            assert str(bss.uptime) == "--"
            assert str(bss.rssi) in ("-60", "-70")

    def test_session_granted(self, caplog):
        cw = FakeInterface(networks=[granted_network()])
        backend = MacOSBackend(fake_corewlan(cw))
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        asyncio.run(session.scan())
        assert "Location Services" not in caplog.text
        (bss,) = session.data
        assert str(bss.ssid) == "Wi-Fi 7"
        assert str(bss.security) == "PSK,SAE/CCMP-128/CCMP-128"

    def test_open_or_wep_not_guessed(self):
        """no RSN/WPA IE and no capability field: do not claim open"""
        ies = bytes([0, 4]) + b"open" + bytes([1, 1, 0x82])
        network = granted_network()
        network._ies = ies
        cw = FakeInterface(networks=[network])
        backend = MacOSBackend(fake_corewlan(cw))
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        asyncio.run(session.scan())
        bss = session.data[0]
        assert (str(bss.security), str(bss.auth), str(bss.encryption)) == (
            "NONE?",
            "NONE?",
            "NONE?",
        )

    def test_rsn_decides_over_missing_capability(self):
        """an RSN IE still decides security with capability=0"""
        cw = FakeInterface(networks=[granted_network()])
        backend = MacOSBackend(fake_corewlan(cw))
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        asyncio.run(session.scan())
        bss = session.data[0]
        assert str(bss.security) == "PSK,SAE/CCMP-128/CCMP-128"
        assert "?" not in str(bss.auth) and "?" not in str(bss.encryption)

    @pytest.mark.parametrize("capability, expected", [(0x0011, "WEP"), (0x0001, "NONE")])
    def test_windows_privacy_bit_unaffected(self, capability, expected):
        """a record with a real capability field keeps NONE vs WEP"""
        ies = bytes([0, 4]) + b"open" + bytes([1, 1, 0x82])
        record = BssRecord(
            ssid=b"open",
            bssid="02:00:00:00:00:01",
            frequency_mhz=2412,
            capability=capability,
            ies=ies,
        )
        bss = WirelessNetworkBss(record)
        assert (str(bss.security), str(bss.auth)) == (expected, expected)
        assert str(bss.encryption) == "NONE"

    @pytest.mark.parametrize(
        "argv, expected",
        [
            (["-channel"], "INTERFACE: en0, MAC: c0:c7:db:00:00:01, CHANNEL: 44"),
            (["-ap", "-channel", "-raw"], "aa:bb:cc:dd:ee:ff, 44"),
            (["--supported"], "unsupported on macOS"),
        ],
    )
    def test_interface_info(self, argv, expected):
        backend = MacOSBackend(fake_corewlan(FakeInterface(bssid="AA:BB:CC:DD:EE:FF")))
        out = backend.interface_info(parse(argv), backend.list_interfaces()[0])
        assert expected in out
        if "--supported" in argv:
            assert "AP uptime isn't available on macOS" in out

    def test_get_interfaces_hides_unavailable_fields(self):
        cw = FakeInterface(bssid="AA:BB:CC:DD:EE:FF")
        backend = MacOSBackend(fake_corewlan(cw))
        iface = backend.list_interfaces()[0]
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Bus:" not in out
        assert "GUID" not in out
        assert "unsupported" not in out
        assert "Channel: 44" in out
        assert "Band: 5 GHz" in out
        assert "Transmit (Tx) Rate: 286 Mbps" in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["bus"] is None
        assert info["tx_rate_mbps"] == 286.0

    def test_fractional_tx_rate(self):
        cw = FakeInterface(bssid="aa:bb:cc:dd:ee:ff")
        cw.transmitRate = lambda: 6.5
        backend = MacOSBackend(fake_corewlan(cw))
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert "Transmit (Tx) Rate: 6.5 Mbps" in out

    def test_list_interfaces_hides_empty_guid(self, capsys):
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        with pytest.raises(SystemExit):
            app.run(parse(["--list-interfaces"]), backend=backend)
        out = capsys.readouterr().out
        assert "Connection Name: en0" in out
        assert "GUID" not in out
        assert "MAC: c0:c7:db:00:00:01" in out

    def test_list_interfaces_json_keeps_null_guid(self, capsys):
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        with pytest.raises(SystemExit):
            app.run(parse(["--list-interfaces", "--json"]), backend=backend)
        payload = json.loads(capsys.readouterr().out)
        assert payload["interfaces"][0]["guid"] is None
        assert payload["interfaces"][0]["mac"] == "c0:c7:db:00:00:01"


def test_import_does_not_load_corewlan():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, lswifi.backends.macos, lswifi.backends.factory; "
            "print('CoreWLAN' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def _corewlan_available():
    if sys.platform != "darwin":
        return False
    try:
        import CoreWLAN  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _corewlan_available(), reason="needs macOS with CoreWLAN")
class TestRealScan:
    def test_scan(self):
        backend = MacOSBackend()
        ifaces = backend.list_interfaces()
        if not ifaces or ifaces[0].state_string == "powered off":
            pytest.skip("no powered-on Wi-Fi interface")
        records = backend.scan(ifaces[0])
        assert all(isinstance(r, BssRecord) for r in records)
        for record in records:
            # parses whether or not Location Services redacted it
            WirelessNetworkBss(record)
