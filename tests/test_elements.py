# -*- encoding: utf-8

import sys

import pytest

import lswifi

# WirelessNetworkBss


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
