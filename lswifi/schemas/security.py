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
lswifi.security
~~~~~~~~~~~~~~~

schema definition for security
"""

from .out import Alignment, Header, OutObject, SubHeader


class Security(OutObject):
    """Base class for Security"""

    def __init__(self, capabilities):
        if capabilities.ci.bits.PRIVACY == 1:
            self.value = "WEP"
        else:
            self.value = "NONE"
        self.header = Header("SECURITY", Alignment.LEFT)
        self.subheader = SubHeader("[auth/unicast/group]")

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"


class SecurityGeneration(OutObject):
    def __init__(self):
        self.value = ""
        self.header = Header("SECURITY", Alignment.LEFT)
        self.subheader = SubHeader("[generation]")
        self.wpa = False
        self.rsn = False
        self.akms = set()
        self.pairwise = []
        self.group = 0
        self.mfpc = False
        self.mfpr = False

    def record_wpa(self):
        self.wpa = True

    def record_rsn(self, akms, pairwise, group, mfpc, mfpr):
        self.rsn = True
        self.akms = set(akms)
        self.pairwise = pairwise
        self.group = group
        self.mfpc = bool(mfpc)
        self.mfpr = bool(mfpr)

    def resolve(self, privacy):
        parts = set()
        if self.rsn:
            if self.akms & {8, 9, 24, 25}:
                parts.add("WPA3")
            if self.akms & {2, 4, 6, 19, 20}:
                parts.add("WPA2")
            if self.akms & {3, 5}:
                if self.mfpc:
                    parts.add("WPA3")
                    if not self.mfpr:
                        parts.add("WPA2")
                else:
                    parts.add("WPA2")
            if self.akms & {12, 13}:
                if 9 in self.pairwise and self.group == 9 and self.mfpr:
                    parts.add("WPA3-192")
                else:
                    parts.add("WPA2")
            if self.akms - {2, 3, 4, 5, 6, 8, 9, 12, 13, 18, 19, 20, 24, 25}:
                parts.add("WPA2")
            if not parts:
                if 18 in self.akms:
                    parts.add("OWE")
                else:
                    parts.add("WPA2")
        if self.wpa:
            parts.add("WPA")
        if parts:
            self.value = "/".join(
                p for p in ["WPA", "WPA2", "WPA3", "WPA3-192", "OWE"] if p in parts
            )
        elif not self.rsn and not self.wpa:
            self.value = "WEP" if privacy else "Open"

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
