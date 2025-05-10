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
lswifi.modes
~~~~~~~~~~~~

schema definition for modes
"""

from collections.abc import MutableSequence

from .out import *


class Modes(MutableSequence):
    def __init__(self, *args, **kwargs):
        self.elements = []
        self.extend(list(args))
        self.header = Header(kwargs.get("header", ""))
        self.subheader = SubHeader(kwargs.get("subheader", ""))

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __delitem__(self, index):
        del self.list[index]

    def __getitem__(self, index):
        return self.list[index]

    def __setitem__(self, index, value):
        self.elements[index] = value

    def insert(self, index, value):
        self.elements.insert(index, value)

    def __len__(self):
        return len(self.elements)

    def __contains__(self, value):
        return value in self.elements

    def __iter__(self):
        return iter(self.elements)

    def __str__(self):
        order = {1: "a", 2: "b", 3: "g", 4: "n", 5: "ac", 6: "ax"}
        actual = {}
        for mode in self.elements:
            for num, phy in order.items():
                if mode == phy:
                    actual[num] = phy
        sorted(actual)
        return "/".join(list(actual.values()))
