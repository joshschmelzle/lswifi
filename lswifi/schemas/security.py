# -*- coding: utf-8 -*-

"""
lswifi.security
~~~~~~~~~~~~~~~

schema definition for security
"""

from .out import *


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
