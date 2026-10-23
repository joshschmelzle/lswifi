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
lswifi.channel
~~~~~~~~~~~~~~

schema definition for channel
"""

from lswifi.helpers import get_channel_number_from_frequency

from .out import *


class ChannelNumber(OutObject):
    """Base class for Channel Number"""

    def __init__(self, frequency_mhz: int):
        """:param frequency_mhz: channel center frequency in MHz"""
        self.frequency = str(frequency_mhz)
        self.value = get_channel_number_from_frequency(str(int(frequency_mhz)))
        self.header = Header("CHANNEL")
        self.subheader = SubHeader("[#@MHz]")
