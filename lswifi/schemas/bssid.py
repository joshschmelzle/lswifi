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
lswifi.bssid
~~~~~~~~~~~~

schema definition for bssid
"""

from lswifi.helpers import convert_mac_address_to_string

from .out import *


class BSSID(OutObject):
    """Base class for BSSID"""

    def __init__(self, bss_entry, connected_bssid, **kwargs):
        self.value = convert_mac_address_to_string(bss_entry.dot11Bssid)
        self.connected_bssid = connected_bssid
        self.connected = False
        if self.value == self.connected_bssid:
            self.connected = True
        self.header = Header(kwargs.get("header", ""), align=kwargs.get("align"))
        self.subheader = SubHeader(kwargs.get("subheader", ""))
