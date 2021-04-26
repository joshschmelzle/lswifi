# -*- coding: utf-8 -*-

"""
lswifi.signalquality
~~~~~~~~~~~~~~~~~~~~

schema definition for signalquality
"""

from .out import *


class SignalQuality(OutObject):
    """Base class for SIGNAL QUALITY"""

    def __init__(self, **kwargs):
        self.value = kwargs.get("value")
        super(SignalQuality, self).__init__(**kwargs)

    def __str__(self):
        return str(f"{self.value}%")
