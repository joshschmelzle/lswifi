# -*- coding: utf-8 -*-

"""
lswifi.phy
~~~~~~~~~~

schema definition for phytype
"""

from lswifi import wlanapi as WLAN_API

from .out import *


class PHYType:
    """Base class for PHY Type"""

    def __init__(self, bss_entry):
        self.value = WLAN_API.DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.header = Header("PHY")
        self.subheader = SubHeader(".11")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.amendment)

    @property
    def generation(self):
        """Get the WFA Generation"""
        return self.get_wfa_generation()

    @property
    def amendment(self):
        """Get the 802.11 amendment"""
        return self.get_amendment()

    @property
    def name(self):
        """Get the current name"""
        return self.value

    @name.setter
    def name(self, value):
        self.value = value

    def get_amendment(self):
        if self.value == "HE":
            return "ax"
        if self.value == "VHT":
            return "ac"
        if self.value == "HT":
            return "n"
        if self.value == "ERP":
            return "g"
        if self.value.replace("-", "") == "HRDSSS":
            return "b"
        if self.value == "OFDM":
            return "a"
        return ""

    def get_wfa_generation(self):
        """
        https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-6
        """
        if self.value == "HE":
            return "6"
        if self.value == "VHT":
            return "5"
        if self.value == "HT":
            return "4"
        if self.value == "ERP":
            return "3"
        if self.value.replace("-", "") == "HRDSSS":
            return "2"
        if self.value == "OFDM":
            return "1"
        return "-"

    def __repr__(self):
        return self.value
