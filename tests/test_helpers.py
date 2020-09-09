# -*- encoding: utf-8

import pytest
import sys

sys.path.insert(0, "../lswifi/")

from _helpers import format_rate

# from _helpers import get_wifi_generation
from _helpers import bytes_to_int
from _helpers import int_to_bytes
from _helpers import format_bytes_as_hex
from _helpers import get_basic_rates
from _helpers import get_data_rates
from _helpers import get_rateset
from _helpers import rate_in_mbps
from _helpers import get_bit
from _helpers import trim_most_significant_bit
from _helpers import convert_mac_address_to_string
from _helpers import strip_mac_address_format
from _helpers import is_two_four_band
from _helpers import is_five_band
from _helpers import get_channel_number


class TestHelpers(object):
    def test_bytes_to_int(self):
        assert bytes_to_int(b"\x00") == 0
        assert bytes_to_int(b"\x8c") == 140
        assert bytes_to_int(b"a") == 97

    def test_int_to_bytes(self):
        assert int_to_bytes(50) == b"2"
        assert int_to_bytes(242) == b"\xf2"
        assert int_to_bytes(127) == b"\x7f"

    def test_format_bytes_as_hex(self):
        assert format_bytes_as_hex(b"xfinitywifi") == "78 66 69 6E 69 74 79 77 69 66 69"
        assert format_bytes_as_hex(b"US \x01\x0b\x1e") == "55 53 20 01 0B 1E"
        assert (
            format_bytes_as_hex(b"\x82\x84\x8b\x96\x0c\x12\x18$")
            == "82 84 8B 96 0C 12 18 24"
        )

    def test_format_rate_(self):
        assert format_rate(1.0) == "1"
        assert format_rate(5.5) == "5.5"
        assert format_rate(24.0) == "24"
        assert format_rate(24) == "24"

    # def test_get_wifi_generation(self):
    #    assert get_wifi_generation("HE") == "6"
    #    assert get_wifi_generation("VHT") == "5"
    #    assert get_wifi_generation("HT") == "4"
    #    assert get_wifi_generation("ERP") == "3"
    #    assert get_wifi_generation("HRDSSS") == "2"
    #    assert get_wifi_generation("HR-DSSS") == "2"
    #    assert get_wifi_generation("OFDM") == "1"

    def test_get_basic_rates(self):
        assert (
            get_basic_rates(
                [32770, 32772, 32779, 32790, 32780, 18, 32792, 36, 32816, 72, 96, 108]
            )
            == "1 2 5.5 11 6 12 24"
        )

    def test_get_data_rates(self):
        assert (
            get_data_rates([32780, 18, 32792, 36, 32816, 72, 96, 108])
            == "9 18 36 48 54"
        )

    def test_get_rateset(self):
        assert (
            get_rateset(
                [32770, 32772, 32779, 32790, 32780, 18, 32792, 36, 32816, 72, 96, 108]
            )
            == "1* 2* 5.5* 6* 11* 12* 24* 9 18 36 48 54"
        )

        assert get_rateset([32816, 72, 96, 108]) == "24* 36 48 54"

    def test_rate_in_mbps(self):
        assert rate_in_mbps(36) == 18.0
        assert rate_in_mbps(11) == 5.5

    def test_get_bit(self):
        assert get_bit(239, 1) == True
        assert get_bit(96, 7) == False

    def test_trim_most_significant_bit(self):
        assert trim_most_significant_bit(176) == 48

    def test_convert_mac_address_to_string(self):
        assert convert_mac_address_to_string([0, 15, 172]) == "00:0f:ac"

    def test_strip_mac_format(self):
        assert strip_mac_address_format("e6:fe:07:66:eb:f8") == "e6fe0766ebf8"
        assert strip_mac_address_format("e6-fe-07-66-eb-f8") == "e6fe0766ebf8"
        assert strip_mac_address_format("e6.fe.07.66.eb.f8") == "e6fe0766ebf8"
        assert strip_mac_address_format("e6fe.0766.ebf8") == "e6fe0766ebf8"

    def test_if_twofour_band(self):
        assert is_two_four_band(2447000) is True

    def test_if_five_band(self):
        assert is_five_band(5240000) is True

    def test_get_channel_number(self):
        assert get_channel_number("2910322") == "Unknown"
        assert get_channel_number("2412000") == "1"
        assert get_channel_number("2417000") == "2"
        assert get_channel_number("2422000") == "3"
        assert get_channel_number("2427000") == "4"
        assert get_channel_number("2432000") == "5"
        assert get_channel_number("2437000") == "6"
        assert get_channel_number("2442000") == "7"
        assert get_channel_number("2447000") == "8"
        assert get_channel_number("2452000") == "9"
        assert get_channel_number("2457000") == "10"
        assert get_channel_number("2462000") == "11"
        assert get_channel_number("2467000") == "12"
        assert get_channel_number("2472000") == "13"
        assert get_channel_number("2484000") == "14"
        assert get_channel_number("5160000") == "32"
        assert get_channel_number("5170000") == "34"
        assert get_channel_number("5180000") == "36"
        assert get_channel_number("5190000") == "38"
        assert get_channel_number("5200000") == "40"
        assert get_channel_number("5210000") == "42"
        assert get_channel_number("5220000") == "44"
        assert get_channel_number("5230000") == "46"
        assert get_channel_number("5240000") == "48"
        assert get_channel_number("5250000") == "50"
        assert get_channel_number("5260000") == "52"
        assert get_channel_number("5270000") == "54"
        assert get_channel_number("5280000") == "56"
        assert get_channel_number("5290000") == "58"
        assert get_channel_number("5300000") == "60"
        assert get_channel_number("5310000") == "62"
        assert get_channel_number("5320000") == "64"
        assert get_channel_number("5340000") == "68"
        assert get_channel_number("5480000") == "96"
        assert get_channel_number("5500000") == "100"
        assert get_channel_number("5510000") == "102"
        assert get_channel_number("5520000") == "104"
        assert get_channel_number("5530000") == "106"
        assert get_channel_number("5540000") == "108"
        assert get_channel_number("5550000") == "110"
        assert get_channel_number("5560000") == "112"
        assert get_channel_number("5570000") == "114"
        assert get_channel_number("5580000") == "116"
        assert get_channel_number("5590000") == "118"
        assert get_channel_number("5600000") == "120"
        assert get_channel_number("5610000") == "122"
        assert get_channel_number("5620000") == "124"
        assert get_channel_number("5630000") == "126"
        assert get_channel_number("5640000") == "128"
        assert get_channel_number("5660000") == "132"
        assert get_channel_number("5670000") == "134"
        assert get_channel_number("5680000") == "136"
        assert get_channel_number("5700000") == "140"
        assert get_channel_number("5710000") == "142"
        assert get_channel_number("5720000") == "144"
        assert get_channel_number("5745000") == "149"
        assert get_channel_number("5755000") == "151"
        assert get_channel_number("5765000") == "153"
        assert get_channel_number("5775000") == "155"
        assert get_channel_number("5785000") == "157"
        assert get_channel_number("5795000") == "159"
        assert get_channel_number("5805000") == "161"
        assert get_channel_number("5825000") == "165"
        assert get_channel_number("5845000") == "169"
        assert get_channel_number("5865000") == "173"
        assert get_channel_number("4915000") == "183"
        assert get_channel_number("4920000") == "184"
        assert get_channel_number("4925000") == "185"
        assert get_channel_number("4935000") == "187"
        assert get_channel_number("4940000") == "188"
        assert get_channel_number("4945000") == "189"
        assert get_channel_number("4960000") == "192"
        assert get_channel_number("4980000") == "196"
