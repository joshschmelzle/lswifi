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
        "OOB_SSID",
        "OOB_BSSID",
        "OOB_RSSI",
        "OOB_CHANNEL",
        "RNR_CHANNEL",
        "RNR_FREQ",
        "RNR_TBTT_OFFSET",
        "RNR_BSSID",
        "RNR_SHORT_SSID",
        "RNR_SAME_SSID",
        "RNR_MULTIPLE_BSSID",
        "RNR_TRANSMITTED_BSSID",
        "RNR_UPR_ACTIVE",
        "RNR_COLOCATED_AP",
        "RNR_TWENTY_MHZ_PSD",
    ],
)


class OOB_BSSID(OutObject):
    """Base class for Discovery BSSID Designation"""

    def __init__(self, ssid=""):
        self.value = ssid
        self.header = Header("BSSID")
        self.subheader = SubHeader("[MAC Address]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class OOB_RSSI(OutObject):
    """Base class for Discovery RSSI Designation"""

    def __init__(self, rssi=""):
        self.value = rssi
        self.header = Header("RSSI")
        self.subheader = SubHeader("dBm")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class OOB_CHANNEL(OutObject):
    """Base class for Discovery CHANNEL Designation"""

    def __init__(self, rssi=""):
        self.value = rssi
        self.header = Header("CHANNEL")
        self.subheader = SubHeader("")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class OOB_SSID(OutObject):
    """Base class for Discovery SSID Designation"""

    def __init__(self, ssid=""):
        self.value = ssid
        self.header = Header("SSID")
        self.subheader = SubHeader("[Network Name]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_TBTT(OutObject):
    """Base class for RNR TBT Designation"""

    def __init__(self, tbtt):
        self.value = tbtt
        self.header = Header("TBTT")
        self.subheader = SubHeader("#")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_TBTT_OFFSET(OutObject):
    """Base class for RNR TBT Offset Designation"""

    def __init__(self, offset):
        self.value = offset
        self.header = Header("TBTT")
        self.subheader = SubHeader("OFFSET (TUs)")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_SHORT_SSID(OutObject):
    """Base class for RNR Short SSID Designation"""

    def __init__(self, shortssid=""):
        self.value = shortssid
        self.header = Header("SHORT SSID")
        self.subheader = SubHeader("[CRC32]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_BSSID(OutObject):
    """Base class for RNR BSSID Designation"""

    def __init__(self, bssid=""):
        self.value = bssid
        self.header = Header("NEIGHBOR BSSID")
        self.subheader = SubHeader("[MAC Address]")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_CHANNEL(OutObject):
    """Base class for RNR Channel Designation"""

    def __init__(self, channel, width):
        self.value = f"{channel}@{width}"
        self.header = Header("NEIGHBOR")
        self.subheader = SubHeader("CHANNEL")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_FREQ(OutObject):
    """Base class for RNR Frequency Designation"""

    def __init__(self, channel):
        self.value = get_6ghz_frequency_from_channel_number(str(channel))
        self.header = Header("NEIGHBOR")
        self.subheader = SubHeader("FREQ.")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_TWENTY_MHZ_PSD(OutObject):
    """Base class for 20 MHz PSD Designation"""

    def __init__(self, psd):
        self.value = psd
        self.header = Header("20 MHz")
        self.subheader = SubHeader("PSD")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_SAME_SSID(OutObject):
    """Base class for Same SSID Designation"""

    def __init__(self, samessid):
        self.value = "Yes" if samessid else "--"
        self.header = Header("SAME")
        self.subheader = SubHeader("SSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_TRANSMITTED_BSSID(OutObject):
    """Base class for Transmitted BSSID Designation"""

    def __init__(self, transmittedbssid):
        self.value = "Yes" if transmittedbssid else "--"
        self.header = Header("TRANSMITTED")
        self.subheader = SubHeader("BSSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_UPR_ACTIVE(OutObject):
    """Base class for UPR Active Designation"""

    def __init__(self, upractive):
        self.value = "Yes" if upractive else "--"
        self.header = Header("UPR")
        self.subheader = SubHeader("ACTIVE")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_MULTIPLE_BSSID(OutObject):
    """Base class for Multiple BSSID Designation"""

    def __init__(self, multiplebssid):
        self.value = "Yes" if multiplebssid else "--"
        self.header = Header("MULTIPLE")
        self.subheader = SubHeader("BSSID")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"


class RNR_COLOCATED_AP(OutObject):
    """Base class for CoLocatedAP Designation"""

    def __init__(self, colocatedap):
        self.value = "Yes" if colocatedap else "--"
        self.header = Header("CO-LOCATED")
        self.subheader = SubHeader("AP")

    def __repr__(self):
        return f"OutObject({self.value},{self.header},{self.subheader})"
