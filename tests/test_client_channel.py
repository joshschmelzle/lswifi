"""-channel band and frequency on Windows, with the WLAN calls faked."""

import json
from types import SimpleNamespace

import pytest

from lswifi import appsetup, wlanapi
from lswifi.backends.base import BssRecord
from lswifi.client import get_interface_info
from lswifi.elements import WirelessNetworkBss

BSSID = "aa:bb:cc:dd:ee:ff"


def parse(argv):
    return appsetup.setup_parser().parse_args(argv)


def iface():
    return SimpleNamespace(
        connection_name="Wi-Fi",
        description="Wireless",
        guid_string="{11111111-1111-1111-1111-111111111111}",
        mac="02:00:00:00:00:01",
    )


def connection(bssid=BSSID):
    return {
        "isState": "connected",
        "wlanConnectionMode": "wlan_connection_mode_profile",
        "strProfileName": "home",
        "wlanAssociationAttributes": {
            "dot11Ssid": b"home",
            "dot11Bssid": bssid,
            "dot11PhyType": "HE",
            "wlanSignalQuality": 80,
            "ulRxRate": 576000,
            "ulTxRate": 576000,
            "dot11BssType": "Infrastructure",
        },
        "wlanSecurityAttributes": {
            "bSecurityEnabled": True,
            "bOneXEnabled": False,
            "dot11AuthAlgorithm": "WPA3-Personal",
            "dot11CipherAlgorithm": "CCMP-128",
        },
    }


def bss(mhz, bssid=BSSID):
    return WirelessNetworkBss(
        BssRecord(ssid=b"home", bssid=bssid, frequency_mhz=mhz, ies=b"")
    )


def install(monkeypatch, *, channel, networks, bssid=BSSID):
    def query_interface(_iface, param):
        if param == "current_connection":
            return (wlanapi.WLANConnectionAttributes(), connection(bssid))
        if param == "channel_number":
            return (SimpleNamespace(value=channel), None)
        return "failed"

    monkeypatch.setattr(wlanapi.WLAN, "query_interface", staticmethod(query_interface))
    monkeypatch.setattr(
        wlanapi.WLAN,
        "get_wireless_network_bss_list",
        staticmethod(lambda *_args, **_kwargs: networks),
    )
    monkeypatch.setattr(
        "lswifi.client.get_adapter_bus_info", lambda _guid: (None, None)
    )


class TestWindowsChannel:
    @pytest.mark.parametrize(
        "mhz, band, channel",
        [
            (2412, "2.4 GHz", 1),
            (5180, "5 GHz", 36),
            (5955, "6 GHz", 1),
        ],
    )
    def test_band_comes_from_the_bss_frequency(self, monkeypatch, mhz, band, channel):
        install(monkeypatch, channel=channel, networks=[bss(mhz)])
        radio = iface()
        assert get_interface_info(parse(["-channel"]), radio) == (
            "INTERFACE: Wi-Fi, MAC: 02:00:00:00:00:01, "
            f"CHANNEL: {channel}, BAND: {band}, FREQ: {mhz}"
        )
        assert get_interface_info(parse(["-ap", "-channel"]), radio) == (
            "INTERFACE: Wi-Fi, MAC: 02:00:00:00:00:01, "
            f"BSSID: {BSSID}, CHANNEL: {channel}, BAND: {band}, FREQ: {mhz}"
        )
        assert get_interface_info(parse(["-channel", "-raw"]), radio) == channel
        assert get_interface_info(parse(["-ap", "-channel", "-raw"]), radio) == (
            f"{BSSID}, {channel}"
        )
        assert get_interface_info(parse(["-ap"]), radio) == (
            f"INTERFACE: Wi-Fi, MAC: 02:00:00:00:00:01, BSSID: {BSSID}"
        )
        info = json.loads(get_interface_info(parse(["-channel", "--json"]), radio))
        assert list(info) == ["interface", "mac", "channel", "band", "freq_mhz"]
        assert info["channel"] == channel
        assert isinstance(info["channel"], int)
        assert info["band"] == band
        assert info["freq_mhz"] == mhz
        both = json.loads(
            get_interface_info(parse(["-ap", "-channel", "--json"]), radio)
        )
        assert list(both) == [
            "interface",
            "mac",
            "bssid",
            "channel",
            "band",
            "freq_mhz",
        ]
        ap = json.loads(get_interface_info(parse(["-ap", "--json"]), radio))
        assert list(ap) == ["interface", "mac", "bssid"]

    def test_channel_number_does_not_choose_the_band(self, monkeypatch):
        """Channel 1 is 2.4 GHz or 6 GHz; the BSS center frequency decides."""
        install(monkeypatch, channel=1, networks=[bss(5955)])
        text = get_interface_info(parse(["-channel"]), iface())
        assert "CHANNEL: 1, BAND: 6 GHz, FREQ: 5955" in text
        assert "2.4 GHz" not in text

    def test_omits_band_when_the_bss_is_missing(self, monkeypatch):
        install(
            monkeypatch, channel=69, networks=[bss(2412, bssid="02:00:00:00:00:02")]
        )
        radio = iface()
        assert get_interface_info(parse(["-channel"]), radio) == (
            "INTERFACE: Wi-Fi, MAC: 02:00:00:00:00:01, CHANNEL: 69"
        )
        info = json.loads(get_interface_info(parse(["-channel", "--json"]), radio))
        assert list(info) == ["interface", "mac", "channel"]
        assert info["channel"] == 69

    def test_omits_band_when_the_bss_list_fails(self, monkeypatch):
        def explode(*_args, **_kwargs):
            raise OSError("bss list unavailable")

        install(monkeypatch, channel=44, networks=[])
        monkeypatch.setattr(
            wlanapi.WLAN, "get_wireless_network_bss_list", staticmethod(explode)
        )
        radio = iface()
        assert get_interface_info(parse(["-channel"]), radio) == (
            "INTERFACE: Wi-Fi, MAC: 02:00:00:00:00:01, CHANNEL: 44"
        )
        assert get_interface_info(parse(["-channel", "-raw"]), radio) == 44
        info = json.loads(get_interface_info(parse(["-channel", "--json"]), radio))
        assert "band" not in info and "freq_mhz" not in info
