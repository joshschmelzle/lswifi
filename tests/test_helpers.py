# -*- encoding: utf-8

import sys

import pytest

from lswifi import helpers

# sys.path.insert(0, "../lswifi/")



class TestHelpers(object):
    def test_bytes_to_int(self):
        assert helpers.bytes_to_int(b"\x00") == 0
        assert helpers.bytes_to_int(b"\x8c") == 140
        assert helpers.bytes_to_int(b"a") == 97

    def test_int_to_bytes(self):
        assert helpers.int_to_bytes(50) == b"2"
        assert helpers.int_to_bytes(242) == b"\xf2"
        assert helpers.int_to_bytes(127) == b"\x7f"

    def test_format_bytes_as_hex(self):
        assert (
            helpers.format_bytes_as_hex(b"xfinitywifi")
            == "78 66 69 6E 69 74 79 77 69 66 69"
        )
        assert helpers.format_bytes_as_hex(b"US \x01\x0b\x1e") == "55 53 20 01 0B 1E"
        assert (
            helpers.format_bytes_as_hex(b"\x82\x84\x8b\x96\x0c\x12\x18$")
            == "82 84 8B 96 0C 12 18 24"
        )

    def test_get_bit(self):
        assert helpers.get_bit(239, 1) == True
        assert helpers.get_bit(96, 7) == False

    def test_trim_most_significant_bit(self):
        assert helpers.trim_most_significant_bit(176) == 48

    def test_convert_mac_address_to_string(self):
        assert helpers.convert_mac_address_to_string([0, 15, 172]) == "00:0f:ac"

    def test_strip_mac_format(self):
        assert helpers.strip_mac_address_format("e6:fe:07:66:eb:f8") == "e6fe0766ebf8"
        assert helpers.strip_mac_address_format("e6-fe-07-66-eb-f8") == "e6fe0766ebf8"
        assert helpers.strip_mac_address_format("e6.fe.07.66.eb.f8") == "e6fe0766ebf8"
        assert helpers.strip_mac_address_format("e6fe.0766.ebf8") == "e6fe0766ebf8"

    def test_if_twofour_band(self):
        assert helpers.is_two_four_band(2447000) is True

    def test_if_five_band(self):
        assert helpers.is_five_band(5240000) is True

    def test_get_channel_number(self):
        print(helpers.get_channel_number_from_frequency("2910322"))
        assert helpers.get_channel_number_from_frequency("2910322") == "Unknown"
        assert helpers.get_channel_number_from_frequency("2412") == "1"
        assert helpers.get_channel_number_from_frequency("2417") == "2"
        assert helpers.get_channel_number_from_frequency("2422") == "3"
        assert helpers.get_channel_number_from_frequency("2427") == "4"
        assert helpers.get_channel_number_from_frequency("2432") == "5"
        assert helpers.get_channel_number_from_frequency("2437") == "6"
        assert helpers.get_channel_number_from_frequency("2442") == "7"
        assert helpers.get_channel_number_from_frequency("2447") == "8"
        assert helpers.get_channel_number_from_frequency("2452") == "9"
        assert helpers.get_channel_number_from_frequency("2457") == "10"
        assert helpers.get_channel_number_from_frequency("2462") == "11"
        assert helpers.get_channel_number_from_frequency("2467") == "12"
        assert helpers.get_channel_number_from_frequency("2472") == "13"
        assert helpers.get_channel_number_from_frequency("2484") == "14"
        assert helpers.get_channel_number_from_frequency("5160") == "32"
        assert helpers.get_channel_number_from_frequency("5170") == "34"
        assert helpers.get_channel_number_from_frequency("5180") == "36"
        assert helpers.get_channel_number_from_frequency("5190") == "38"
        assert helpers.get_channel_number_from_frequency("5200") == "40"
        assert helpers.get_channel_number_from_frequency("5210") == "42"
        assert helpers.get_channel_number_from_frequency("5220") == "44"
        assert helpers.get_channel_number_from_frequency("5230") == "46"
        assert helpers.get_channel_number_from_frequency("5240") == "48"
        assert helpers.get_channel_number_from_frequency("5250") == "50"
        assert helpers.get_channel_number_from_frequency("5260") == "52"
        assert helpers.get_channel_number_from_frequency("5270") == "54"
        assert helpers.get_channel_number_from_frequency("5280") == "56"
        assert helpers.get_channel_number_from_frequency("5290") == "58"
        assert helpers.get_channel_number_from_frequency("5300") == "60"
        assert helpers.get_channel_number_from_frequency("5310") == "62"
        assert helpers.get_channel_number_from_frequency("5320") == "64"
        assert helpers.get_channel_number_from_frequency("5340") == "68"
        assert helpers.get_channel_number_from_frequency("5480") == "96"
        assert helpers.get_channel_number_from_frequency("5500") == "100"
        assert helpers.get_channel_number_from_frequency("5510") == "102"
        assert helpers.get_channel_number_from_frequency("5520") == "104"
        assert helpers.get_channel_number_from_frequency("5530") == "106"
        assert helpers.get_channel_number_from_frequency("5540") == "108"
        assert helpers.get_channel_number_from_frequency("5550") == "110"
        assert helpers.get_channel_number_from_frequency("5560") == "112"
        assert helpers.get_channel_number_from_frequency("5570") == "114"
        assert helpers.get_channel_number_from_frequency("5580") == "116"
        assert helpers.get_channel_number_from_frequency("5590") == "118"
        assert helpers.get_channel_number_from_frequency("5600") == "120"
        assert helpers.get_channel_number_from_frequency("5610") == "122"
        assert helpers.get_channel_number_from_frequency("5620") == "124"
        assert helpers.get_channel_number_from_frequency("5630") == "126"
        assert helpers.get_channel_number_from_frequency("5640") == "128"
        assert helpers.get_channel_number_from_frequency("5660") == "132"
        assert helpers.get_channel_number_from_frequency("5670") == "134"
        assert helpers.get_channel_number_from_frequency("5680") == "136"
        assert helpers.get_channel_number_from_frequency("5700") == "140"
        assert helpers.get_channel_number_from_frequency("5710") == "142"
        assert helpers.get_channel_number_from_frequency("5720") == "144"
        assert helpers.get_channel_number_from_frequency("5745") == "149"
        assert helpers.get_channel_number_from_frequency("5755") == "151"
        assert helpers.get_channel_number_from_frequency("5765") == "153"
        assert helpers.get_channel_number_from_frequency("5775") == "155"
        assert helpers.get_channel_number_from_frequency("5785") == "157"
        assert helpers.get_channel_number_from_frequency("5795") == "159"
        assert helpers.get_channel_number_from_frequency("5805") == "161"
        assert helpers.get_channel_number_from_frequency("5825") == "165"
        assert helpers.get_channel_number_from_frequency("5845") == "169"
        assert helpers.get_channel_number_from_frequency("5865") == "173"
        assert helpers.get_channel_number_from_frequency("4915") == "183"
        assert helpers.get_channel_number_from_frequency("4920") == "184"
        assert helpers.get_channel_number_from_frequency("4925") == "185"
        assert helpers.get_channel_number_from_frequency("4935") == "187"
        assert helpers.get_channel_number_from_frequency("4940") == "188"
        assert helpers.get_channel_number_from_frequency("4945") == "189"
        assert helpers.get_channel_number_from_frequency("4960") == "192"
        assert helpers.get_channel_number_from_frequency("4980") == "196"
