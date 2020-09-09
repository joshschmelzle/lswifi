# -*- coding: utf-8 -*-

"""
lswifi.helpers
~~~~~~~~~~~~~~~

Provides helper functions that are consumed internally.
"""

import random
from enum import Enum
from .constants import _20MHZ_CHANNEL_LIST
from ctypes import c_ubyte
from typing import Union


class OUT_TUPLE:
    def __init__(self, value, header=None, subheader=None):
        self.value = value
        self.header = header
        self.subheader = subheader
        self._len = len(value)

    def __len__(self):
        return self._len

    def __str__(self):
        return self.value

    def __repr__(self):
        print(f"OUT_TUPLE({self.value},{self.header},{self.subheader}")


class Alignment(Enum):
    NONE = ""
    LEFT = "<"
    CENTER = "^"
    RIGHT = ">"
    LEFTMOST = "="


class SubHeader:
    def __init__(self, description):
        self.description = description
        self.value = description
        self._len = len(description)

    def __str__(self):
        return self.description

    def __format__(self, format_spec):
        return format("{}".format(self.description), format_spec)

    def __len__(self):
        return self._len

    def __repr__(self):
        return self.description


class Header:
    def __init__(self, description, align=None):
        self.description = description
        self.value = description
        self._len = len(description)
        if align:
            self.alignment = align
        else:
            self.alignment = Alignment.NONE

    def __str__(self):
        return self.description

    def __format__(self, format_spec):
        return format("{}".format(self.description), format_spec)

    def __len__(self):
        return self._len

    def __repr__(self):
        return self.description


def generate_pretty_separator(_len, separators, begin, end):
    out = begin
    count = 0
    custom = _len - 2
    while count < custom:
        out += random.choice(separators)
        count = count + 1
    out = out + end
    return out


def get_attr_max_len(ies, attr):
    _list = []
    for ie in ies:
        if isinstance(getattr(ie, attr), str):
            # getattr(ie, attr)
            _list.append(getattr(ie, attr))
        else:
            _list.append(str(getattr(ie, attr)))
    return max(len(x) for x in _list)


def bytes_to_int(x_bytes):
    return int.from_bytes(x_bytes, "big")


def int_to_bytes(_int):
    return _int.to_bytes((_int.bit_length() + 7) // 8, "big")


def format_bytes_as_hex(_bytes):
    """
    format a bytes in two digit hex string
    doesn't seem to work with lists
    TODO: add exception handling?
    """
    out = ""
    for _int in _bytes:
        out = out + f"{_int:02x} "
    return out.upper().strip()


def format_rate(rate):
    """
    Removes trailing .0 from a <class 'float'>:
    1.0 to 1
    5.5 to 5.5
    """
    out = ""
    if isinstance(rate, int):  # 1, 2, 6, etc
        out = f"{out + str(rate)}"
    elif rate.is_integer():  # 1.0, 2.0, 6.0, 9.0 etc
        out = f"{out + str(int(rate))}"
    else:  # 5.5, etc.
        out = f"{out + str(rate)}"
    return out


def get_basic_rates(WlanRateSet):
    out = ""
    for rate in WlanRateSet:
        if rate.bit_length() == 16:  # basic rate
            rate_bytes = int_to_bytes(rate)
            out += f"{format_rate(rate_to_mbps(rate_bytes[1]))} "
    return out.strip()


def get_data_rates(WlanRateSet):
    out = ""
    for rate in WlanRateSet:
        if rate.bit_length() == 16:  # basic rate
            pass
        else:
            out += f"{format_rate(rate_to_mbps(rate))} "
    return out.strip()


def get_rateset(WlanRateSet):
    out = ""
    basics = []
    supported = []
    for rate in WlanRateSet:
        if rate.bit_length() == 16:  # basic rate
            rate_bytes = int_to_bytes(rate)
            basics.append(format_rate(rate_to_mbps(rate_bytes[1])))
        else:
            supported.append(format_rate(rate_to_mbps(rate)))
    basics.sort(key=float)
    supported.sort(key=float)
    basics = [basic + "*" for basic in basics]
    out = " ".join(basics) + " " + " ".join(supported)
    return out.strip()


def flag_last_object(seq):
    """ treat the last object in an iterable differently """
    seq = iter(seq)  # ensure this is an iterator
    a = next(seq)
    for b in seq:
        yield a, False
        a = b
    yield a, True


def rate_to_mbps(rate):
    """ convert raw 802.11 rate to mbps """
    return (rate & 0x7FFF) * 0.5


def get_bit(byteval, index) -> bool:
    """ retrieve bit value from byte at provided index """
    return (byteval & (1 << index)) != 0


def bools_to_binary_string(_list: list) -> str:
    return "0b" + "".join(["1" if x else "0" for x in _list])


def binary_string_to_int(binary_string: str) -> int:
    return int(binary_string[2:], 2)


def trim_most_significant_bit(byteval: int) -> int:
    """ trim the most significant bit """
    return byteval & 0x7F


def convert_mac_address_to_string(mac: Union[list, c_ubyte]) -> str:
    """returns a MAC address in string format
    input can be a list or a c_ubyte from the wlanapi.h
    """
    return ":".join("%02x" % x for x in mac)


def strip_mac_address_format(mac):
    """normalizes the various mac address formats"""
    return mac.lower().replace("-", "").replace(".", "").replace(":", "")


def __get_digit(number, n):
    """internal helper to get the value of a number at a certain position"""
    return number // 10 ** n % 10


def __num_digits(num: int):
    """internal helper to get the number of digits"""
    return len(str(num))


def is_two_four_band(channel):  # TODO: would a hash lookup table be faster?
    """determines if a channel frequency is in the 2.4 GHz ISM band"""
    if __get_digit(channel, __num_digits(channel) - 1) == 2:
        return True
    else:
        return False


def is_five_band(channel):  # TODO: would a hash lookup table be faster?
    """detremines if a channel frequency is in the 5.0 GHz ISM band"""
    if __get_digit(channel, __num_digits(channel) - 1) == 5:
        return True
    else:
        return False


def get_channel_number_from_frequency(frequency):
    """gets the 802.11 channel for a corresponding frequency
    in units of kilohertz (kHz). does not support FHSS."""
    try:
        return _20MHZ_CHANNEL_LIST.get(frequency)
    except KeyError:
        return "Unknown"
