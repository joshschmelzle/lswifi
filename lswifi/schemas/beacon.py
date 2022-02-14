# -*- coding: utf-8 -*-

"""
lswifi.beacon
~~~~~~~~~~~~~

schema definition for beacon
"""

from .out import *


class BeaconInterval(OutObject):
    """Base class for Beacon Interval"""

    def __init__(self, **kwargs):
        super(BeaconInterval, self).__init__(**kwargs)
        self.value = self.get_beacon_interval(kwargs.get("value"))

    def __str__(self):
        return f"{self.value}"

    def get_beacon_interval(self, beaconperiod):
        """
        Beacons are sent by the AP at a regular interval defined as the Target Beacon Transmission Time (TBTT).

        The TBTT is a time interval measured in time units (TUs). A TU is equal to 1024 microseconds.

        The TU is often confused with 1 ms.

        The reality is seen in the definition of a time unit in the 802.11-2012 standard document, which reads, "A measurement of time equal to 1024 µs."
        """
        return (1024 * beaconperiod) / 1000
