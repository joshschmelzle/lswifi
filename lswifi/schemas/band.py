# -*- coding: utf-8 -*-
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
lswifi.band
~~~~~~~~~~~

schema definition for band [2,5,6]
"""

from lswifi.helpers import is_five_band, is_six_band, is_two_four_band

from .out import *


class Band(OutObject):
    """Base class for Band Designation"""

    def __init__(self, frequency):
        self.is_2ghz = is_two_four_band(frequency)
        self.is_5ghz = is_five_band(frequency)
        self.is_6ghz = is_six_band(frequency)
        band = None
        if self.is_6ghz:
            band = "6GHz"
        if self.is_5ghz:
            band = "5GHz"
        if self.is_2ghz:
            band = "2GHz"
        if band:
            self.value = band
        else:
            self.value = ""
        self.header = Header("BAND")
        self.subheader = SubHeader("")
