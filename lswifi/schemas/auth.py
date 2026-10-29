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
lswifi.auth
~~~~~~~~~~~~~~~

schema definition for auth
"""

from lswifi.constants import AKM_SUITE_DICT

from .out import *

FT_PAIRS = {1: 3, 5: 3, 2: 4, 8: 9, 12: 13, 14: 16, 15: 17, 20: 19, 23: 22, 24: 25}
FT_TWINS = {AKM_SUITE_DICT[base]: AKM_SUITE_DICT[ft] for base, ft in FT_PAIRS.items()}


class Auth(OutObject):
    """Base class for auth"""

    def __init__(self, capabilities):
        if capabilities.ci.bits.PRIVACY == 1:
            self.value = "WEP"
        else:
            self.value = "NONE"
        self.header = Header("AUTH", Alignment.LEFT)
        self.subheader = SubHeader("[akm]")

    def out(self):
        akms = str(self.value).split(",")
        merged = set()
        for akm in akms:
            twin = FT_TWINS.get(akm)
            if twin in akms and twin not in merged:
                merged.add(twin)
        shown = []
        used = set()
        for akm in akms:
            twin = FT_TWINS.get(akm)
            if twin in merged and twin not in used:
                used.add(twin)
                shown.append(f"{akm}+FT")
            elif akm not in merged:
                shown.append(akm)
        return OUT_TUPLE(",".join(shown), self.header, self.subheader)

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
