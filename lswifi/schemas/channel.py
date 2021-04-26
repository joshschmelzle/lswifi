# -*- coding: utf-8 -*-

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
