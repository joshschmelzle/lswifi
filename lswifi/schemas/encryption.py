# -*- coding: utf-8 -*-

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
