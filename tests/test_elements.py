# -*- encoding: utf-8

import pytest
import sys

sys.path.insert(0, "../lswifi")

import wlanapi as WLAN_API
from elements import WirelessNetworkBss


class TestElements:
    def test_parse_rates(self):
        assert (
            WirelessNetworkBss.parse_rates(
                "1(b) 2(b) 5.5(b) 11(b) 6(b) 9 12(b) 18 24(b) 36 48 54"
            )
            == "1* 2* 5.5* 6* 9 11* 12* 18 24* 36 48 54"
        )
        assert (
            WirelessNetworkBss.parse_rates(
                "1(b) 2(b) 5.5(b) 11(b) 18 24 36 54 6 9 12 48"
            )
            == "1* 2* 5.5* 6 9 11* 12 18 24 36 48 54"
        )
        assert (
            WirelessNetworkBss.parse_rates("6(b) 9 12(b) 18 24(b) 36 48 54")
            == "6* 9 12* 18 24* 36 48 54"
        )

    def test_convert_timestamp_to_uptime(self):
        assert (
            WirelessNetworkBss.convert_timestamp_to_uptime(13667420576596)
            == "158d 4:30:20"
        )
        assert (
            WirelessNetworkBss.convert_timestamp_to_uptime(179295494144)
            == "02d 1:48:15"
        )
        assert (
            WirelessNetworkBss.convert_timestamp_to_uptime(285837076) == "00d 0:04:45"
        )
