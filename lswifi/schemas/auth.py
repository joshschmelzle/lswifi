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

from .out import *

FT_TWINS = {
    ".1X": "FT-.1X",
    ".1X-SHA256": "FT-.1X",
    "PSK": "FT-PSK",
    "SAE": "FT-SAE",
    ".1X-CNSA-SHA384": "FT-.1X-SHA384",
    ".1X-SHA384": "FT-.1X-SHA384",
    "FILS-SHA256": "FT-FILS-SHA256",
    "FILS-SHA384": "FT-FILS-SHA384",
    "PSK-SHA384": "FT-PSK-SHA384",
    "SAE-GDH": "FT-SAE-GDH",
}


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
