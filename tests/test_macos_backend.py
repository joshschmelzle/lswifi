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
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from lswifi import app, appsetup
from lswifi.backends import macos, macos_location
from lswifi.backends.base import BackendError, BssRecord
from lswifi.backends.macos import (
    MacOSBackend,
    MacOSScanSession,
    frequency_from_channel,
    network_to_record,
)
from lswifi.elements import WirelessNetworkBss

_REAL_PREPARE = macos_location.prepare_location_services

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
    from lswifi.backends import macos_location

    monkeypatch.setattr(macos, "_location_warned", False)
    monkeypatch.setattr(macos_location, "_cached", None)
    monkeypatch.setattr(
        macos_location,
        "prepare_location_services",
        lambda: macos_location.LocationAuthorization("authorized", True, ""),
    )


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
        assert "authorized for this Python" in warnings[0].getMessage()
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


def _sample_channels():
    channels = []
    for number in range(1, 15):
        for width in (1, 2):
            channels.append(FakeChannel(number, macos.CW_CHANNEL_BAND_2GHZ, width))
    five = list(range(36, 65, 4)) + list(range(100, 145, 4)) + list(range(149, 166, 4))
    for number in five:
        for width in (1, 2, 3, 4):
            channels.append(FakeChannel(number, macos.CW_CHANNEL_BAND_5GHZ, width))
    for number in range(1, 234, 4):
        for width in (1, 2, 3, 4):
            channels.append(FakeChannel(number, macos.CW_CHANNEL_BAND_6GHZ, width))
    return channels


class _WifiMonitor:
    """CWIPMonitor selectors observed on macOS: no ipv4State."""

    def ipv4WiFiStateConfig(self):
        return {
            "ARPResolvedHardwareAddress": "64:e8:81:b8:e9:80",
            "ARPResolvedIPAddress": "192.168.1.1",
            "AdditionalRoutes": [],
        }

    def ipv4Router(self):
        return "10.9.9.9"

    def ipv4Addresses(self):
        return ["192.168.1.50", "10.1.1.5"]


class RichInterface(FakeInterface):
    def __init__(self):
        super().__init__(bssid="AA:BB:CC:DD:EE:FF")
        self.calls = []

    def ssidData(self):
        return b"office"

    def activePHYMode(self):
        self.calls.append("activePHYMode")
        return 7

    def security(self):
        self.calls.append("security")
        return 11

    def mcsIndex(self):
        self.calls.append("mcsIndex")
        return 6

    def numberOfSpatialStreams(self):
        return 2

    def maxNSSSupportedForAP(self):
        return 2

    def serviceActive(self):
        return True

    def ipMonitor(self):
        return _WifiMonitor()

    def supportedWLANChannels(self):
        return _sample_channels()

    def transmitPower(self):
        return 10.0


class RaisingInterface(FakeInterface):
    def __init__(self):
        super().__init__(bssid="aa:bb:cc:dd:ee:ff")

    def activePHYMode(self):
        raise RuntimeError("phy")

    def security(self):
        raise RuntimeError("security")

    def mcsIndex(self):
        raise RuntimeError("mcs")

    def numberOfSpatialStreams(self):
        raise RuntimeError("nss")

    def maxNSSSupportedForAP(self):
        raise RuntimeError("max")

    def serviceActive(self):
        raise RuntimeError("service")

    def ipMonitor(self):
        raise RuntimeError("ip")

    def supportedWLANChannels(self):
        raise RuntimeError("channels")


class GuardedInterface(FakeInterface):
    def __init__(self):
        super().__init__(bssid="aa:bb:cc:dd:ee:ff")
        self.calls = []

    def respondsToSelector_(self, selector):
        name = getattr(selector, "selector", None) or selector
        if isinstance(name, bytes):
            name = name.decode()
        blocked = {
            "mcsIndex",
            "numberOfSpatialStreams",
            "maxNSSSupportedForAP",
            "ipMonitor",
            "activePHYMode",
            "security",
            "serviceActive",
            "supportedWLANChannels",
        }
        return str(name) not in blocked

    def mcsIndex(self):
        self.calls.append("mcsIndex")
        return 9

    def activePHYMode(self):
        self.calls.append("activePHYMode")
        return 7


class TestMacInterfaceInfo:
    def test_connected_stats_and_channels(self):
        cw = RichInterface()
        backend = MacOSBackend(fake_corewlan(cw))
        iface = backend.list_interfaces()[0]
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "SSID: office" in out
        assert "PHY Mode: 802.11be" in out
        assert "Security: WPA3 Personal" in out
        assert "MCS: 6" in out
        assert "Spatial Streams: 2" in out
        assert "Max Spatial Streams: 2" in out
        assert "Gateway: 192.168.1.1" in out
        assert "Gateway MAC: 64:e8:81:b8:e9:80" in out
        assert "IPv4 Address: 192.168.1.50, 10.1.1.5" in out
        assert "10.9.9.9" not in out
        assert "Tx Power: 10 mW" in out
        assert "Interface Mode: station" in out
        assert "Power: on" in out
        assert "Service Active: yes" in out
        assert "Supported Channels: 2.4 GHz 1-14 (20/40), " in out
        assert "5 GHz 36-64, 100-144, 149-165 (20/40/80/160)" in out
        assert "6 GHz 1-233 (20/40/80/160)" in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["phy_mode"] == "802.11be"
        assert info["security"] == "WPA3 Personal"
        assert info["mcs_index"] == 6
        assert info["spatial_streams"] == 2
        assert info["max_spatial_streams"] == 2
        assert info["gateway_ip"] == "192.168.1.1"
        assert info["gateway_mac"] == "64:e8:81:b8:e9:80"
        assert info["ipv4_addresses"] == ["192.168.1.50", "10.1.1.5"]
        assert info["tx_power_mw"] == 10.0
        assert info["interface_mode"] == "station"
        assert info["power_on"] is True
        assert info["service_active"] is True
        assert info["supported_channels"][0] == {
            "band": "2.4 GHz",
            "ranges": [[1, 14]],
            "widths_mhz": [20, 40],
        }
        assert info["supported_channels"][2]["band"] == "6 GHz"
        assert info["supported_channels"][2]["ranges"] == [[1, 233]]

    def test_unknown_enum_prints_raw_number(self):
        cw = FakeInterface(bssid="aa:bb:cc:dd:ee:ff")
        cw.activePHYMode = lambda: 99
        cw.security = lambda: 99
        backend = MacOSBackend(fake_corewlan(cw))
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert "PHY Mode: 99" in out
        assert "Security: 99" in out

    def test_gateway_falls_back_to_state_config_then_router(self):
        class StateConfig:
            def ipv4StateConfig(self):
                return {
                    "ARPResolvedIPAddress": "192.168.4.1",
                    "ARPResolvedHardwareAddress": "AA:BB:CC:DD:EE:10",
                }

            def ipv4Router(self):
                return "10.0.0.1"

        cw = FakeInterface(bssid="aa:bb:cc:dd:ee:ff")
        cw.ipMonitor = lambda: StateConfig()
        backend = MacOSBackend(fake_corewlan(cw))
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert "Gateway: 192.168.4.1" in out
        assert "Gateway MAC: aa:bb:cc:dd:ee:10" in out
        assert "10.0.0.1" not in out

        class RouterOnly:
            def ipv4Router(self):
                return "192.168.8.1"

            def ipv4Addresses(self):
                return ["192.168.8.20"]

        cw.ipMonitor = lambda: RouterOnly()
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert "Gateway: 192.168.8.1" in out
        assert "Gateway MAC" not in out
        assert "IPv4 Address: 192.168.8.20" in out

    def test_disconnected_omits_connected_fields(self):
        cw = FakeInterface()
        cw.interfaceMode = lambda: 0
        cw.activePHYMode = lambda: 7
        cw.security = lambda: 11
        cw.mcsIndex = lambda: 6
        cw.numberOfSpatialStreams = lambda: 2
        cw.ipMonitor = lambda: {
            "ipv4State": {
                "ARPResolvedIPAddress": "192.168.1.1",
                "ARPResolvedHardwareAddress": "aa:bb:cc:dd:ee:01",
            }
        }
        backend = MacOSBackend(fake_corewlan(cw))
        iface = backend.list_interfaces()[0]
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "is disconnected" in out
        assert "Interface Mode: none" in out
        assert "Power: on" in out
        for label in (
            "SSID",
            "PHY Mode",
            "Security",
            "MCS",
            "Spatial Streams",
            "Gateway",
            "Transmit (Tx) Rate",
            "RSSI",
        ):
            assert label not in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["state"] == "disconnected"
        assert info["phy_mode"] is None
        assert info["security"] is None
        assert info["mcs_index"] is None
        assert info["spatial_streams"] is None
        assert info["gateway_ip"] is None
        assert info["tx_rate_mbps"] is None
        assert info["interface_mode"] == "none"

    def test_missing_selectors_are_null(self):
        cw = FakeInterface(bssid="aa:bb:cc:dd:ee:ff")
        backend = MacOSBackend(fake_corewlan(cw))
        iface = backend.list_interfaces()[0]
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Tx Power: 17 mW" in out
        assert "Interface Mode: station" in out
        for label in (
            "PHY Mode",
            "Security",
            "MCS",
            "Spatial Streams",
            "Gateway",
            "Service Active",
            "Supported Channels",
        ):
            assert label not in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        for key in (
            "phy_mode",
            "security",
            "mcs_index",
            "spatial_streams",
            "max_spatial_streams",
            "gateway_ip",
            "gateway_mac",
            "ipv4_addresses",
            "service_active",
            "supported_channels",
        ):
            assert info[key] is None

    def test_raising_selectors_are_skipped(self, caplog):
        cw = RaisingInterface()
        backend = MacOSBackend(fake_corewlan(cw))
        with caplog.at_level(logging.WARNING):
            out = backend.interface_info(
                parse(["--get-interfaces"]), backend.list_interfaces()[0]
            )
        assert "PHY Mode" not in out
        assert "Security" not in out
        assert "MCS" not in out
        assert "Supported Channels" not in out
        assert "Service Active" not in out
        assert "Gateway" not in out
        assert caplog.records == []

    def test_responds_to_selector_false_does_not_call(self):
        cw = GuardedInterface()
        backend = MacOSBackend(fake_corewlan(cw))
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert cw.calls == []
        assert "MCS" not in out
        assert "PHY Mode" not in out


def test_import_does_not_load_corewlan():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, lswifi.backends.macos, lswifi.backends.factory; "
            "print("
            "'CoreWLAN' in sys.modules, "
            "'CoreLocation' in sys.modules, "
            "'Foundation' in sys.modules"
            ")",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False False False"


class TestLocationIntegration:
    def _denied(self, monkeypatch):
        state = macos_location.LocationAuthorization(
            "denied",
            False,
            macos_location.DENIED_MESSAGE,
        )
        monkeypatch.setattr(macos_location, "prepare_location_services", lambda: state)
        monkeypatch.setattr(
            macos_location, "current_location_authorization", lambda: state
        )
        return state

    def test_open_session_checks_before_scan(self, monkeypatch):
        calls = []

        def prepare():
            calls.append(threading.current_thread())
            return macos_location.LocationAuthorization("authorized", True, "")

        monkeypatch.setattr(macos_location, "prepare_location_services", prepare)
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        iface = backend.list_interfaces()[0]
        backend.open_session(parse([]), iface)
        assert calls == [threading.current_thread()]
        assert calls[0] is threading.main_thread()
        backend.scan(iface)
        assert len(calls) == 2

    def test_list_interfaces_does_not_ask(self, monkeypatch, capsys):
        def prepare():
            raise AssertionError("location check")

        monkeypatch.setattr(macos_location, "prepare_location_services", prepare)
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        with pytest.raises(SystemExit):
            app.run(parse(["--list-interfaces"]), backend=backend)
        assert "Connection Name: en0" in capsys.readouterr().out

    def test_denied_warns_once_across_scans(self, monkeypatch, caplog):
        self._denied(monkeypatch)
        cw = FakeInterface(networks=[redacted_network(), redacted_network(rssi=-70)])
        backend = MacOSBackend(fake_corewlan(cw))
        session = backend.open_session(parse([]), backend.list_interfaces()[0])
        with caplog.at_level(logging.WARNING):
            asyncio.run(session.scan())
            asyncio.run(session.scan())
        warnings = [r for r in caplog.records if "denied" in r.getMessage()]
        assert [r.getMessage() for r in warnings] == [macos_location.DENIED_MESSAGE]
        assert "app that runs" not in caplog.text

    def test_supported_and_interfaces_report_status(self, monkeypatch):
        self._denied(monkeypatch)
        backend = MacOSBackend(fake_corewlan(FakeInterface(bssid="aa:bb:cc:dd:ee:ff")))
        iface = backend.list_interfaces()[0]
        supported = backend.interface_info(parse(["--supported"]), iface)
        assert "Location Services" not in supported
        assert "unsupported on macOS" in supported
        text = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Location Services: denied" in text
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["location_authorization"] == "denied"

    def test_get_interfaces_json_stays_one_document(self, monkeypatch, capsys, caplog):
        self._denied(monkeypatch)
        backend = MacOSBackend(fake_corewlan(FakeInterface(bssid="aa:bb:cc:dd:ee:ff")))
        with caplog.at_level(logging.WARNING), pytest.raises(SystemExit) as caught:
            app.run(parse(["--get-interfaces", "--json"]), backend=backend)
        assert caught.value.code == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert list(out.strip())[0] == "{"
        assert payload["location_authorization"] == "denied"
        assert "System Settings" not in out
        assert [r.getMessage() for r in caplog.records] == [
            macos_location.DENIED_MESSAGE
        ]

    def test_bare_warning_uses_prepared_denial_when_uncached(self, monkeypatch, caplog):
        state = macos_location.LocationAuthorization(
            "denied",
            False,
            macos_location.DENIED_MESSAGE,
        )
        monkeypatch.setattr(macos_location, "prepare_location_services", lambda: state)
        with caplog.at_level(logging.WARNING):
            macos.warn_location_once()
            macos.warn_location_once()
        assert [r.getMessage() for r in caplog.records] == [
            macos_location.DENIED_MESSAGE
        ]

    def test_watch_events_checks_location_before_the_run_loop(self, monkeypatch):
        order = []

        def prepare():
            order.append("location")
            return macos_location.LocationAuthorization("authorized", True, "")

        class Watcher:
            def __init__(self, *_args, **_kwargs):
                order.append("init")

            def run(self):
                order.append("run")

        monkeypatch.setattr(macos_location, "prepare_location_services", prepare)
        monkeypatch.setattr("lswifi.backends.macos_events.MacOSEventWatcher", Watcher)
        backend = MacOSBackend(fake_corewlan(FakeInterface()))
        backend.watch_events(parse(["--watchevents"]))
        assert order == ["location", "init", "run"]

    def test_authorized_interface_has_no_warning(self, caplog):
        backend = MacOSBackend(fake_corewlan(FakeInterface(bssid="aa:bb:cc:dd:ee:ff")))
        iface = backend.list_interfaces()[0]
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Location Services: authorized" in out
        assert "Location Services" not in caplog.text


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
    def test_scan(self, monkeypatch):
        monkeypatch.setattr(macos_location, "prepare_location_services", _REAL_PREPARE)
        monkeypatch.setattr(macos_location, "_cached", None)
        backend = MacOSBackend()
        ifaces = backend.list_interfaces()
        if not ifaces or ifaces[0].state_string == "powered off":
            pytest.skip("no powered-on Wi-Fi interface")
        records = backend.scan(ifaces[0])
        assert all(isinstance(r, BssRecord) for r in records)
        for record in records:
            # parses whether or not Location Services redacted it
            WirelessNetworkBss(record)
