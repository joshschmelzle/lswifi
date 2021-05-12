# -*- coding: utf-8 -*-

"""
lswifi.helpers
~~~~~~~~~~~~~~

Provides helper functions that are consumed internally.
"""

import json
import random
from base64 import b64encode

from .constants import _20MHZ_CHANNEL_LIST


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


def flag_last_object(seq):
    """treat the last object in an iterable differently"""
    seq = iter(seq)  # ensure this is an iterator
    a = next(seq)
    for b in seq:
        yield a, False
        a = b
    yield a, True


def get_bit(byteval, index) -> bool:
    """retrieve bit value from byte at provided index"""
    return (byteval & (1 << index)) != 0


def bools_to_binary_string(_list: list) -> str:
    return "0b" + "".join(["1" if x else "0" for x in _list])


def binary_string_to_int(binary_string: str) -> int:
    return int(binary_string[2:], 2)


def trim_most_significant_bit(byteval: int) -> int:
    """trim the most significant bit"""
    return byteval & 0x7F


def convert_mac_address_to_string(mac) -> str:
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


def is_two_four_band(frequency: int) -> bool:
    """determines if a channel frequency is in the 2.4 GHz ISM band"""
    if __get_digit(frequency, __num_digits(frequency) - 1) == 2:
        return True
    else:
        return False


def is_five_band(frequency: int) -> bool:
    """determines if a channel frequency is in the 5.0 GHz ISM band"""
    if __get_digit(frequency, __num_digits(frequency) - 1) == 5:
        return True
    else:
        return False


def is_six_band(frequency: int) -> bool:
    """determines if a channel frequency is in the 6.0-7.125 GHz ISM band"""
    if frequency > 5900 and frequency < 7125:
        return True
    else:
        return False


def get_channel_number_from_frequency(frequency):
    """gets the 802.11 channel for a corresponding frequency
    in units of kilohertz (kHz). does not support FHSS."""
    try:
        return _20MHZ_CHANNEL_LIST.get(frequency, "Unknown")
    except KeyError:
        return "Unknown"


class Base64Encoder(json.JSONEncoder):
    """A Base64 encoder for JSON"""

    # example usage: json.dumps(bytes(frame), cls=Base64Encoder)

    # pylint: disable=method-hidden
    def default(self, obj):
        """Perform default Base64 encode"""
        if isinstance(obj, bytes):
            return b64encode(obj).decode()
        return json.JSONEncoder.default(self, obj)
