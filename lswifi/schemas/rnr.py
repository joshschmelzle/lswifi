# -*- coding: utf-8 -*-

"""
lswifi.rnr
~~~~~~~~~~

schema definition for Reduced Neighbor Report (RNR IE 201)
"""

from collections import namedtuple

from lswifi.helpers import get_6ghz_frequency_from_channel_number
from lswifi.schemas.out import Header, OutObject, SubHeader

# Declaring namedtuple()
RNR = namedtuple(
    "RNR",
    [
        "DetectingBSSID",
        "DetectingRSSI",
        "SSID",
        "ShortSSID",
        "BSSID",
        "Channel",
        "Freq",
        "TBTT",
        "Offset",
        "TwentyMHzPSD",
        "SameSSID",
        "TransmittedBSSID",
        "UPRActive",
        "CoLocatedAP",
    ],
)


class TBTT(OutObject):
    """Base class for RNR TBT Designation"""

    def __init__(self, tbtt):
        self.value = tbtt
        self.header = Header("TBTT")
        self.subheader = SubHeader("#")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class Offset(OutObject):
    """Base class for RNR TBT Offset Designation"""

    def __init__(self, offset):
        self.value = offset
        self.header = Header("Offset")
        self.subheader = SubHeader("")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class DiscoveryBSSID(OutObject):
    """Base class for Discovery BSSID Designation"""

    def __init__(self, ssid=""):
        self.value = ssid
        self.header = Header("BSSID")
        self.subheader = SubHeader("Discovery")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class DiscoveryRSSI(OutObject):
    """Base class for Discovery RSSI Designation"""

    def __init__(self, rssi=""):
        self.value = rssi
        self.header = Header("RSSI")
        self.subheader = SubHeader("Discovery")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class DiscoveryChannel(OutObject):
    """Base class for Discovery RSSI Designation"""

    def __init__(self, rssi=""):
        self.value = rssi
        self.header = Header("RSSI")
        self.subheader = SubHeader("Discovery")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RSSID(OutObject):
    """Base class for RNR SSID Designation"""

    def __init__(self, ssid=""):
        self.value = ssid
        self.header = Header("SSID")
        self.subheader = SubHeader("If Same SSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class SHORTSSID(OutObject):
    """Base class for RNR Short SSID Designation"""

    def __init__(self, shortssid=""):
        self.value = shortssid
        self.header = Header("Short SSID")
        self.subheader = SubHeader("[CRC32]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RBSSID(OutObject):
    """Base class for RNR BSSID Designation"""

    def __init__(self, bssid=""):
        self.value = bssid
        self.header = Header("BSSID")
        self.subheader = SubHeader("[MAC]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RCHANNEL(OutObject):
    """Base class for RNR Channel Designation"""

    def __init__(self, channel, width):
        self.value = f"{channel}@{width}"
        self.header = Header("CHANNEL")
        self.subheader = SubHeader("[#@MHz]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RFREQ(OutObject):
    """Base class for RNR Frequency Designation"""

    def __init__(self, channel):
        self.value = get_6ghz_frequency_from_channel_number(str(channel))
        self.header = Header("FREQ.")
        self.subheader = SubHeader("[GHz]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class TwentyMHzPSD(OutObject):
    """Base class for 20 MHz PSD Designation"""

    def __init__(self, psd):
        self.value = psd
        self.header = Header("20 MHz")
        self.subheader = SubHeader("PSD")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class SameSSID(OutObject):
    """Base class for Same SSID Designation"""

    def __init__(self, samessid):
        self.value = "Yes" if samessid else "--"
        self.header = Header("Same")
        self.subheader = SubHeader("SSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class TransmittedBSSID(OutObject):
    """Base class for Transmitted BSSID Designation"""

    def __init__(self, transmittedbssid):
        self.value = "Yes" if transmittedbssid else "--"
        self.header = Header("Transmitted")
        self.subheader = SubHeader("BSSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class UPRActive(OutObject):
    """Base class for UPR Active Designation"""

    def __init__(self, upractive):
        self.value = "Yes" if upractive else "--"
        self.header = Header("UPR")
        self.subheader = SubHeader("Active")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class CoLocatedAP(OutObject):
    """Base class for CoLocatedAP Designation"""

    def __init__(self, colocatedap):
        self.value = "Yes" if colocatedap else "--"
        self.header = Header("CoLocated")
        self.subheader = SubHeader("AP")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"
