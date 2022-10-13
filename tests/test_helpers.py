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
        assert helpers.is_two_four_band(2447) is True
        assert helpers.is_two_four_band(5240) is False
        assert helpers.is_two_four_band(5905) is False
        assert helpers.is_two_four_band(6215) is False
        assert helpers.is_two_four_band(7115) is False
        assert helpers.is_two_four_band(2.447) is True
        assert helpers.is_two_four_band(5.240) is False
        assert helpers.is_two_four_band(5.905) is False
        assert helpers.is_two_four_band(6.215) is False
        assert helpers.is_two_four_band(7.115) is False

    def test_if_five_band(self):
        assert helpers.is_five_band(2412) is False
        assert helpers.is_five_band(5240) is True
        assert helpers.is_five_band(5905) is True
        assert helpers.is_five_band(5975) is False
        assert helpers.is_five_band(6215) is False
        assert helpers.is_five_band(7115) is False
        assert helpers.is_five_band(2.412) is False
        assert helpers.is_five_band(5.240) is True
        assert helpers.is_five_band(5.905) is True
        assert helpers.is_five_band(5.975) is False
        assert helpers.is_five_band(6.215) is False
        assert helpers.is_five_band(7.115) is False
        
    def test_if_six_band(self):
        assert helpers.is_six_band(2447) is False
        assert helpers.is_six_band(5240) is False
        assert helpers.is_six_band(5975) is True
        assert helpers.is_six_band(6215) is True
        assert helpers.is_six_band(7115) is True
        assert helpers.is_six_band(2.447) is False
        assert helpers.is_six_band(5.240) is False
        assert helpers.is_six_band(5.975) is True
        assert helpers.is_six_band(6.215) is True
        assert helpers.is_six_band(7.115) is True

    def test_get_channel_number(self):
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
        assert helpers.get_channel_number_from_frequency("5885") == "177"
        assert helpers.get_channel_number_from_frequency("5905") == "181"
        assert helpers.get_channel_number_from_frequency("5955") == "1"
        assert helpers.get_channel_number_from_frequency("5975") == "5"
        assert helpers.get_channel_number_from_frequency("5995") == "9"
        assert helpers.get_channel_number_from_frequency("6015") == "13"
        assert helpers.get_channel_number_from_frequency("6035") == "17"
        assert helpers.get_channel_number_from_frequency("6055") == "21"
        assert helpers.get_channel_number_from_frequency("6075") == "25"
        assert helpers.get_channel_number_from_frequency("6095") == "29"
        assert helpers.get_channel_number_from_frequency("6115") == "33"
        assert helpers.get_channel_number_from_frequency("6135") == "37"
        assert helpers.get_channel_number_from_frequency("6155") == "41"
        assert helpers.get_channel_number_from_frequency("6175") == "45"
        assert helpers.get_channel_number_from_frequency("6195") == "49"
        assert helpers.get_channel_number_from_frequency("6215") == "53"
        assert helpers.get_channel_number_from_frequency("6235") == "57"
        assert helpers.get_channel_number_from_frequency("6255") == "61"
        assert helpers.get_channel_number_from_frequency("6275") == "65"
        assert helpers.get_channel_number_from_frequency("6295") == "69"
        assert helpers.get_channel_number_from_frequency("6315") == "73"
        assert helpers.get_channel_number_from_frequency("6335") == "77"
        assert helpers.get_channel_number_from_frequency("6355") == "81"
        assert helpers.get_channel_number_from_frequency("6375") == "85"
        assert helpers.get_channel_number_from_frequency("6395") == "89"
        assert helpers.get_channel_number_from_frequency("6415") == "93"
        assert helpers.get_channel_number_from_frequency("6435") == "97"
        assert helpers.get_channel_number_from_frequency("6455") == "101"
        assert helpers.get_channel_number_from_frequency("6475") == "105"
        assert helpers.get_channel_number_from_frequency("6495") == "109"
        assert helpers.get_channel_number_from_frequency("6515") == "113"
        assert helpers.get_channel_number_from_frequency("6535") == "117"
        assert helpers.get_channel_number_from_frequency("6555") == "121"
        assert helpers.get_channel_number_from_frequency("6575") == "125"
        assert helpers.get_channel_number_from_frequency("6595") == "129"
        assert helpers.get_channel_number_from_frequency("6615") == "133"
        assert helpers.get_channel_number_from_frequency("6635") == "137"
        assert helpers.get_channel_number_from_frequency("6655") == "141"
        assert helpers.get_channel_number_from_frequency("6675") == "145"
        assert helpers.get_channel_number_from_frequency("6695") == "149"
        assert helpers.get_channel_number_from_frequency("6715") == "153"
        assert helpers.get_channel_number_from_frequency("6735") == "157"
        assert helpers.get_channel_number_from_frequency("6755") == "161"
        assert helpers.get_channel_number_from_frequency("6775") == "165"
        assert helpers.get_channel_number_from_frequency("6795") == "169"
        assert helpers.get_channel_number_from_frequency("6815") == "173"
        assert helpers.get_channel_number_from_frequency("6835") == "177"
        assert helpers.get_channel_number_from_frequency("6855") == "181"
        assert helpers.get_channel_number_from_frequency("6875") == "185"
        assert helpers.get_channel_number_from_frequency("6895") == "189"
        assert helpers.get_channel_number_from_frequency("6915") == "193"
        assert helpers.get_channel_number_from_frequency("6935") == "197"
        assert helpers.get_channel_number_from_frequency("6955") == "201"
        assert helpers.get_channel_number_from_frequency("6975") == "205"
        assert helpers.get_channel_number_from_frequency("6995") == "209"
        assert helpers.get_channel_number_from_frequency("7015") == "213"
        assert helpers.get_channel_number_from_frequency("7035") == "217"
        assert helpers.get_channel_number_from_frequency("7055") == "221"
        assert helpers.get_channel_number_from_frequency("7075") == "225"
        assert helpers.get_channel_number_from_frequency("7095") == "229"
        assert helpers.get_channel_number_from_frequency("7115") == "233"
        assert helpers.get_channel_number_from_frequency("2.910322") == "Unknown"
        assert helpers.get_channel_number_from_frequency("2.412") == "1"
        assert helpers.get_channel_number_from_frequency("2.417") == "2"
        assert helpers.get_channel_number_from_frequency("2.422") == "3"
        assert helpers.get_channel_number_from_frequency("2.427") == "4"
        assert helpers.get_channel_number_from_frequency("2.432") == "5"
        assert helpers.get_channel_number_from_frequency("2.437") == "6"
        assert helpers.get_channel_number_from_frequency("2.442") == "7"
        assert helpers.get_channel_number_from_frequency("2.447") == "8"
        assert helpers.get_channel_number_from_frequency("2.452") == "9"
        assert helpers.get_channel_number_from_frequency("2.457") == "10"
        assert helpers.get_channel_number_from_frequency("2.462") == "11"
        assert helpers.get_channel_number_from_frequency("2.467") == "12"
        assert helpers.get_channel_number_from_frequency("2.472") == "13"
        assert helpers.get_channel_number_from_frequency("2.484") == "14"
        assert helpers.get_channel_number_from_frequency("5.160") == "32"
        assert helpers.get_channel_number_from_frequency("5.170") == "34"
        assert helpers.get_channel_number_from_frequency("5.180") == "36"
        assert helpers.get_channel_number_from_frequency("5.190") == "38"
        assert helpers.get_channel_number_from_frequency("5.200") == "40"
        assert helpers.get_channel_number_from_frequency("5.210") == "42"
        assert helpers.get_channel_number_from_frequency("5.220") == "44"
        assert helpers.get_channel_number_from_frequency("5.230") == "46"
        assert helpers.get_channel_number_from_frequency("5.240") == "48"
        assert helpers.get_channel_number_from_frequency("5.250") == "50"
        assert helpers.get_channel_number_from_frequency("5.260") == "52"
        assert helpers.get_channel_number_from_frequency("5.270") == "54"
        assert helpers.get_channel_number_from_frequency("5.280") == "56"
        assert helpers.get_channel_number_from_frequency("5.290") == "58"
        assert helpers.get_channel_number_from_frequency("5.300") == "60"
        assert helpers.get_channel_number_from_frequency("5.310") == "62"
        assert helpers.get_channel_number_from_frequency("5.320") == "64"
        assert helpers.get_channel_number_from_frequency("5.340") == "68"
        assert helpers.get_channel_number_from_frequency("5.480") == "96"
        assert helpers.get_channel_number_from_frequency("5.500") == "100"
        assert helpers.get_channel_number_from_frequency("5.510") == "102"
        assert helpers.get_channel_number_from_frequency("5.520") == "104"
        assert helpers.get_channel_number_from_frequency("5.530") == "106"
        assert helpers.get_channel_number_from_frequency("5.540") == "108"
        assert helpers.get_channel_number_from_frequency("5.550") == "110"
        assert helpers.get_channel_number_from_frequency("5.560") == "112"
        assert helpers.get_channel_number_from_frequency("5.570") == "114"
        assert helpers.get_channel_number_from_frequency("5.580") == "116"
        assert helpers.get_channel_number_from_frequency("5.590") == "118"
        assert helpers.get_channel_number_from_frequency("5.600") == "120"
        assert helpers.get_channel_number_from_frequency("5.610") == "122"
        assert helpers.get_channel_number_from_frequency("5.620") == "124"
        assert helpers.get_channel_number_from_frequency("5.630") == "126"
        assert helpers.get_channel_number_from_frequency("5.640") == "128"
        assert helpers.get_channel_number_from_frequency("5.660") == "132"
        assert helpers.get_channel_number_from_frequency("5.670") == "134"
        assert helpers.get_channel_number_from_frequency("5.680") == "136"
        assert helpers.get_channel_number_from_frequency("5.700") == "140"
        assert helpers.get_channel_number_from_frequency("5.710") == "142"
        assert helpers.get_channel_number_from_frequency("5.720") == "144"
        assert helpers.get_channel_number_from_frequency("5.745") == "149"
        assert helpers.get_channel_number_from_frequency("5.755") == "151"
        assert helpers.get_channel_number_from_frequency("5.765") == "153"
        assert helpers.get_channel_number_from_frequency("5.775") == "155"
        assert helpers.get_channel_number_from_frequency("5.785") == "157"
        assert helpers.get_channel_number_from_frequency("5.795") == "159"
        assert helpers.get_channel_number_from_frequency("5.805") == "161"
        assert helpers.get_channel_number_from_frequency("5.825") == "165"
        assert helpers.get_channel_number_from_frequency("5.845") == "169"
        assert helpers.get_channel_number_from_frequency("5.865") == "173"
        assert helpers.get_channel_number_from_frequency("5.885") == "177"
        assert helpers.get_channel_number_from_frequency("5.905") == "181"
        assert helpers.get_channel_number_from_frequency("5.955") == "1"
        assert helpers.get_channel_number_from_frequency("5.975") == "5"
        assert helpers.get_channel_number_from_frequency("5.995") == "9"
        assert helpers.get_channel_number_from_frequency("6.015") == "13"
        assert helpers.get_channel_number_from_frequency("6.035") == "17"
        assert helpers.get_channel_number_from_frequency("6.055") == "21"
        assert helpers.get_channel_number_from_frequency("6.075") == "25"
        assert helpers.get_channel_number_from_frequency("6.095") == "29"
        assert helpers.get_channel_number_from_frequency("6.115") == "33"
        assert helpers.get_channel_number_from_frequency("6.135") == "37"
        assert helpers.get_channel_number_from_frequency("6.155") == "41"
        assert helpers.get_channel_number_from_frequency("6.175") == "45"
        assert helpers.get_channel_number_from_frequency("6.195") == "49"
        assert helpers.get_channel_number_from_frequency("6.215") == "53"
        assert helpers.get_channel_number_from_frequency("6.235") == "57"
        assert helpers.get_channel_number_from_frequency("6.255") == "61"
        assert helpers.get_channel_number_from_frequency("6.275") == "65"
        assert helpers.get_channel_number_from_frequency("6.295") == "69"
        assert helpers.get_channel_number_from_frequency("6.315") == "73"
        assert helpers.get_channel_number_from_frequency("6.335") == "77"
        assert helpers.get_channel_number_from_frequency("6.355") == "81"
        assert helpers.get_channel_number_from_frequency("6.375") == "85"
        assert helpers.get_channel_number_from_frequency("6.395") == "89"
        assert helpers.get_channel_number_from_frequency("6.415") == "93"
        assert helpers.get_channel_number_from_frequency("6.435") == "97"
        assert helpers.get_channel_number_from_frequency("6.455") == "101"
        assert helpers.get_channel_number_from_frequency("6.475") == "105"
        assert helpers.get_channel_number_from_frequency("6.495") == "109"
        assert helpers.get_channel_number_from_frequency("6.515") == "113"
        assert helpers.get_channel_number_from_frequency("6.535") == "117"
        assert helpers.get_channel_number_from_frequency("6.555") == "121"
        assert helpers.get_channel_number_from_frequency("6.575") == "125"
        assert helpers.get_channel_number_from_frequency("6.595") == "129"
        assert helpers.get_channel_number_from_frequency("6.615") == "133"
        assert helpers.get_channel_number_from_frequency("6.635") == "137"
        assert helpers.get_channel_number_from_frequency("6.655") == "141"
        assert helpers.get_channel_number_from_frequency("6.675") == "145"
        assert helpers.get_channel_number_from_frequency("6.695") == "149"
        assert helpers.get_channel_number_from_frequency("6.715") == "153"
        assert helpers.get_channel_number_from_frequency("6.735") == "157"
        assert helpers.get_channel_number_from_frequency("6.755") == "161"
        assert helpers.get_channel_number_from_frequency("6.775") == "165"
        assert helpers.get_channel_number_from_frequency("6.795") == "169"
        assert helpers.get_channel_number_from_frequency("6.815") == "173"
        assert helpers.get_channel_number_from_frequency("6.835") == "177"
        assert helpers.get_channel_number_from_frequency("6.855") == "181"
        assert helpers.get_channel_number_from_frequency("6.875") == "185"
        assert helpers.get_channel_number_from_frequency("6.895") == "189"
        assert helpers.get_channel_number_from_frequency("6.915") == "193"
        assert helpers.get_channel_number_from_frequency("6.935") == "197"
        assert helpers.get_channel_number_from_frequency("6.955") == "201"
        assert helpers.get_channel_number_from_frequency("6.975") == "205"
        assert helpers.get_channel_number_from_frequency("6.995") == "209"
        assert helpers.get_channel_number_from_frequency("7.015") == "213"
        assert helpers.get_channel_number_from_frequency("7.035") == "217"
        assert helpers.get_channel_number_from_frequency("7.055") == "221"
        assert helpers.get_channel_number_from_frequency("7.075") == "225"
        assert helpers.get_channel_number_from_frequency("7.095") == "229"
        assert helpers.get_channel_number_from_frequency("7.115") == "233"