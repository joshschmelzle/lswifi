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

from .out import OUT_TUPLE, Alignment, Header, OutObject, SubHeader


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
        self.group_mgmt = 0
        self.mfpc = False
        self.mfpr = False
        self.nonconformant = []

    def record_wpa(self):
        self.wpa = True

    def record_rsn(self, akms, pairwise, group, group_mgmt, mfpc, mfpr):
        self.rsn = True
        self.akms = set(akms)
        self.pairwise = pairwise
        self.group = group
        self.group_mgmt = group_mgmt
        self.mfpc = bool(mfpc)
        self.mfpr = bool(mfpr)

    def resolve(self, privacy, six_ghz=False):
        parts = set()
        if self.rsn:
            if self.akms & {8, 9, 24, 25} and self.mfpc:
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
                if (
                    self.akms == {12}
                    and set(self.pairwise) == {9}
                    and self.group == 9
                    and self.group_mgmt == 12
                    and self.mfpr
                ):
                    parts.add("WPA3-192")
                elif self.mfpc:
                    parts.add("WPA3")
                else:
                    parts.add("WPA2")
            if self.akms - {2, 3, 4, 5, 6, 8, 9, 12, 13, 18, 19, 20, 24, 25}:
                parts.add("WPA2")
            if not parts:
                if self.akms & {8, 9, 24, 25}:
                    parts.add("SAE")
                elif 18 in self.akms:
                    parts.add("OWE")
                else:
                    parts.add("WPA2")
        if self.wpa:
            parts.add("WPA")
        if parts:
            self.value = "/".join(
                p
                for p in ["WPA", "WPA2", "WPA3", "WPA3-192", "OWE", "SAE"]
                if p in parts
            )
        elif not self.rsn and not self.wpa:
            self.value = "WEP" if privacy else "Open"
        self.nonconformant = []
        if not six_ghz:
            return
        checks = [
            ("6ghz-wep", not self.rsn and not self.wpa and privacy),
            ("6ghz-open", not self.rsn and not self.wpa and not privacy),
            ("6ghz-tkip", self.rsn and (2 in self.pairwise or self.group == 2)),
            ("6ghz-psk", bool(self.akms & {2, 4, 6, 19, 20})),
            ("6ghz-dot1x-sha1", 1 in self.akms),
            ("6ghz-pmf-not-required", self.rsn and not self.mfpr),
        ]
        self.nonconformant = [code for code, hit in checks if hit]

    def out(self):
        text = f"{self.value}!" if self.nonconformant else self.value or "--"
        return OUT_TUPLE(text, self.header, self.subheader)

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
