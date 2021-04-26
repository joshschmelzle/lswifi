# -*- coding: utf-8 -*-

"""
lswifi.outobject
~~~~~~~~~~~~~~~~

schema definition for outobject

this code helps control the formatting when printing to stdout
"""

from collections.abc import MutableSequence
from enum import Enum


class Alignment(Enum):
    NONE = ""
    LEFT = "<"
    CENTER = "^"
    RIGHT = ">"
    LEFTMOST = "="


class SubHeader:
    def __init__(self, description):
        self.description = description
        self.value = description

    def __str__(self):
        return self.description

    def __format__(self, format_spec):
        return format("{}".format(self.description), format_spec)

    def __len__(self):
        return len(self.description)

    def __repr__(self):
        return self.description


class Header:
    def __init__(self, description, align=None):
        self.description = description
        self.value = description
        if align:
            self.alignment = align
        else:
            self.alignment = Alignment.NONE

    def __str__(self):
        return self.description

    def __format__(self, format_spec):
        return format("{}".format(self.description), format_spec)

    def __len__(self):
        return len(self.description)

    def __repr__(self):
        return self.description


class OUT_TUPLE:
    def __init__(self, value, header=None, subheader=None):
        self.value = value
        self.header = header
        self.subheader = subheader

    def __len__(self):
        return len(self.value)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        print(f"OUT_TUPLE({self.value},{self.header},{self.subheader}")


class OutObject(object):
    """Object for printing out"""

    def __init__(self, **kwargs):
        self.value = kwargs.get("value", "")
        self.header = Header(kwargs.get("header", ""), align=kwargs.get("align", None))
        self.subheader = SubHeader(kwargs.get("subheader", ""))

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value

    def __len__(self):
        return len(str(self.value))


class OutList(MutableSequence):
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
        if all(isinstance(x, int) for x in self.elements):
            self.elements.sort(key=int)
        if all(isinstance(x, str) for x in self.elements):
            self.elements.sort(key=str)
        return "/".join([str(x) for x in self.elements])
