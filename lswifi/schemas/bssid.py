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

from .out import *


class BSSID(OutObject):
    """Base class for BSSID"""

    def __init__(self, bssid: str, connected: bool = False, **kwargs):
        """
        :param bssid: MAC address string, aa:bb:cc:dd:ee:ff
        :param connected: whether the scanning interface is associated to it
        """
        self.value = bssid
        self.connected = connected
        self.header = Header(kwargs.get("header", ""), align=kwargs.get("align"))
        self.subheader = SubHeader(kwargs.get("subheader", ""))
