# -*- encoding: utf-8

import sys

import pytest

import lswifi
import lswifi.elements
from lswifi.backends.base import BssRecord

# WirelessNetworkBss


def _bss_with_ies(ssid, ie_bytes, capability=0x0011):
    ies = bytes([0, len(ssid)]) + ssid + bytes([1, 1, 0x82]) + ie_bytes
    return lswifi.elements.WirelessNetworkBss(
        BssRecord(
            ssid=ssid,
            bssid="02:00:00:00:00:10",
            frequency_mhz=2437,
            capability=capability,
            ies=ies,
        )
    )


class TestElements:
    def test_parse_rates(self):
        test1 = lswifi.elements.OutObject(
            value="1(b) 2(b) 5.5(b) 11(b) 6(b) 9 12(b) 18 24(b) 36 48 54"
        )

        test2 = lswifi.elements.OutObject(
            value="1(b) 2(b) 5.5(b) 11(b) 18 24 36 54 6 9 12 48"
        )

        test3 = lswifi.elements.OutObject(value="6(b) 9 12(b) 18 24(b) 36 48 54")

        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test1)
            == "1(B) 2(B) 5.5(B) 6(B) 9 11(B) 12(B) 18 24(B) 36 48 54"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test2)
            == "1(B) 2(B) 5.5(B) 6 9 11(B) 12 18 24 36 48 54"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test3)
            == "6(B) 9 12(B) 18 24(B) 36 48 54"
        )

    def test_convert_timestamp_to_uptime(self):
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(
                13667420576596
            )
            == "158d 4:30:20"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(179295494144)
            == "02d 1:48:15"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(285837076)
            == "00d 0:04:45"
        )

    @pytest.mark.parametrize(
        "wpa_ie, auth, encryption, security",
        [
            pytest.param(
                "dd160050f20101000050f20201000050f20201000050f202",
                "PSK",
                "TKIP",
                "PSK/TKIP/TKIP",
                id="wpa-psk-tkip",
            ),
            pytest.param(
                "dd160050f20101000050f20401000050f20401000050f201",
                ".1X-SHA-1",
                "CCMP-128",
                ".1X-SHA-1/CCMP-128/CCMP-128",
                id="wpa-1x-ccmp",
            ),
        ],
    )
    def test_legacy_wpa_ie(self, wpa_ie, auth, encryption, security):
        bss = _bss_with_ies(b"legacy", bytes.fromhex(wpa_ie))
        assert (str(bss.auth), str(bss.encryption), str(bss.security)) == (
            auth,
            encryption,
            security,
        )
        decoded = next(ie.decoded for ie in bss.information_elements if ie.eid == 221)
        assert decoded.startswith("Microsoft WPA Version: 1,")
        assert auth in decoded
        assert encryption.split("/")[0] in decoded

    def test_legacy_wpa_alongside_rsn(self):
        rsn = bytes.fromhex("30140100000fac020100000fac040100000fac020000")
        wpa = bytes.fromhex("dd160050f20101000050f20201000050f20201000050f202")
        bss = _bss_with_ies(b"mixed", rsn + wpa)
        assert str(bss.auth) == "PSK"
        assert str(bss.encryption) == "CCMP-128,TKIP/TKIP"
        assert str(bss.security) == "PSK/CCMP-128,TKIP/TKIP"
        decoded = next(ie.decoded for ie in bss.information_elements if ie.eid == 221)
        assert "TKIP" in decoded and "PSK" in decoded
