# -*- coding: utf-8 -*-

"""
lswifi.auth
~~~~~~~~~~~~~~~

schema definition for auth
"""

from .out import *


class Auth(OutObject):
    """Base class for auth"""

    def __init__(self, capabilities):
        if capabilities.ci.bits.PRIVACY == 1:
            self.value = "WEP"
        else:
            self.value = "NONE"
        self.header = Header("AUTH", Alignment.LEFT)
        self.subheader = SubHeader("[akm]")

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"
