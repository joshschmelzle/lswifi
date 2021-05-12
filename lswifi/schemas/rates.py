# -*- coding: utf-8 -*-

"""
lswifi.rates
~~~~~~~~~~~~

schema definition for rates
"""


class Rates:
    """Base class for rates of a BSS"""

    def __init__(self, bss_entry):
        self.basic = get_basic_rates(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )

        self.data = get_data_rates(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )

        self.rate_set = get_rateset(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )


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
