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
lswifi.encryption
~~~~~~~~~~~~~~~

schema definition for encryption
"""

from .out import *


class Encryption(OutObject):
    """Base class for Encryption"""

    def __init__(self):
        self.header = Header("ENCRYPTION", Alignment.LEFT)
        self.subheader = SubHeader("[unicast/group]")
        self.value = "NONE"

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
