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
lswifi.pmf
~~~~~~~~~~~~~~~

schema definition for pmf
"""

from .out import *


class PMF(OutObject):
    """Base class for Protected Management Frame (PMF) a.k.a Management Frame Protection (MFP)"""

    def __init__(self):
        self.value = "Disabled"
        self.header = Header("PMF", Alignment.LEFT)
        self.subheader = SubHeader("[.11w]")

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
