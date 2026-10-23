#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

"""
lswifi.rates
~~~~~~~~~~~~

schema definition for rates
"""


class Rates:
    """Base class for rates of a BSS"""

    def __init__(self, rate_set):
        """:param rate_set: rates in WLAN_RATE_SET units (bit 15 marks basic)"""
        self.basic = get_basic_rates(rate_set)

        self.data = get_data_rates(rate_set)

        self.rate_set = get_rateset(rate_set)

    @classmethod
    def from_ies(cls, ies):
        """Build from the Supported Rates (1) and Extended Supported Rates (50)
        elements, for backends that do not report a rate set."""
        return cls(get_rateset_from_ies(ies))


# BSS membership selector values (bits 0-6) carried in the rates elements
BSS_MEMBERSHIP_SELECTOR_VALUES = range(121, 128)


def get_rateset_from_ies(ies):
    """
    Walk an IE TLV chain and convert the Supported Rates and Extended
    Supported Rates octets to WLAN_RATE_SET units. BSS membership selectors
    are not rates and are skipped. A truncated trailing element is ignored.
    """
    rate_set = []
    ies = bytes(ies)
    index = 0
    while index + 2 <= len(ies):
        element_id = ies[index]
        length = ies[index + 1]
        body = ies[index + 2 : index + 2 + length]
        if len(body) < length:
            break
        if element_id in (1, 50):
            for octet in body:
                value = octet & 0x7F
                if value in BSS_MEMBERSHIP_SELECTOR_VALUES:
                    continue
                rate_set.append(0x8000 | value if octet & 0x80 else value)
        index += 2 + length
    return rate_set


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


def rate_to_mbps(rate):
    """convert raw 802.11 rate to mbps"""
    return (rate & 0x7FFF) * 0.5


def int_to_bytes(_int):
    return _int.to_bytes((_int.bit_length() + 7) // 8, "big")


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
    basics = [basic + "(B)" for basic in basics]
    out = " ".join(basics) + " " + " ".join(supported)
    return out.strip()
