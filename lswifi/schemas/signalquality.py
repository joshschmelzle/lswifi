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
lswifi.signalquality
~~~~~~~~~~~~~~~~~~~~

schema definition for signalquality
"""

from .out import *


class SignalQuality(OutObject):
    """Base class for SIGNAL QUALITY"""

    def __init__(self, **kwargs):
        self.value = kwargs.get("value")
        super(SignalQuality, self).__init__(**kwargs)

    def __str__(self):
        return str(f"{self.value}%")
