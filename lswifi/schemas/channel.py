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

    def __init__(self, bss_entry):
        self.frequency = str(bss_entry.ChCenterFrequency)
        self.value = get_channel_number_from_frequency(
            str(int(bss_entry.ChCenterFrequency / 1000))
        )
        self.header = Header("CHANNEL")
        self.subheader = SubHeader("[#@MHz]")
