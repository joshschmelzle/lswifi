# -*- coding: utf-8 -*-

"""
lswifi.pmf
~~~~~~~~~~~~~~~

schema definition for pmf
"""

from .out import *


class PMF(OutObject):
    """Base class for Protected Management Frame (PMF) a.k.a Management Frame Protection (MFP)"""

    def __init__(self):
        self.value = "--"
        self.header = Header("MFP", Alignment.LEFT)
        self.subheader = SubHeader("[.11w]")

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
