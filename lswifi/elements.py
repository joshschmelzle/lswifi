# -*- coding: utf-8 -*-

"""
lswifi.elements
~~~~~~~~~~~~~~~

code used to parse the information elements provided by Native Wifi's wlanapi.h
"""

import math
import collections
from dataclasses import dataclass
from datetime import timedelta
from ctypes import addressof
from ctypes import c_char
from struct import unpack_from
import logging

from . import wlanapi as WLAN_API
from .constants import *
from .constants import (
    _40MHZ_CHANNEL_LIST,
    _20MHZ_CHANNEL_LIST,
    _80MHZ_CHANNEL_LIST,
    _160MHZ_CHANNEL_LIST,
)
from .helpers import *


class Rates:
    """Base class for rates of a BSS"""

    def __init__(self, bss_entry):
        self.basic = get_basic_rates(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )

        self.data = get_data_rates(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )

        self.rate_set = get_rateset(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        )


class SSID:
    """Base class for SSID"""

    def __init__(self, bss_entry):
        self.value = bytes.decode(
            bss_entry.dot11Ssid.SSID[: WLAN_API.DOT11_SSID_MAX_LENGTH]
        )
        self.header = Header("ESSID", Alignment.RIGHT)
        self.subheader = SubHeader("[Network Name]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class IERates:
    """Base class for RSSI"""

    def __init__(self):
        self.value = ""
        self.header = Header("SUPPORTED RATES", Alignment.CENTER)
        self.subheader = SubHeader("(*): basic rates [Mbit/s]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class BSSID:
    """Base class for BSSID"""

    def __init__(self, bss_entry, connected_bssid):
        self.value = convert_mac_address_to_string(bss_entry.dot11Bssid)
        self.connected_bssid = connected_bssid
        self.connected = False
        if self.value == self.connected_bssid:
            self.connected = True
        self.header = Header("BSSID")
        self.subheader = SubHeader("")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class RSSI:
    """Base class for RSSI"""

    def __init__(self, rssi):
        self.value = rssi
        self.header = Header("RSSI")
        self.subheader = SubHeader("[dBm]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class APName:
    """Base class for AP Name"""

    def __init__(self):
        self.value = ""
        self.header = Header("AP NAME")
        self.subheader = SubHeader("")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class DTIM:
    """Base class for DTIM"""

    def __init__(self):
        self.value = ""
        self.header = Header("DTIM")
        self.subheader = SubHeader("")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class ACM:
    """Base class for ACM"""

    def __init__(self, ac):
        self.value = ""
        self.header = Header(f"AC_{ac}")
        self.subheader = SubHeader("ACM")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class SignalQuality:
    """Base class for SIGANL QUALITY"""

    def __init__(self, link_quality):
        self.value = link_quality
        self.header = Header("SIG")
        self.subheader = SubHeader("QUA")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(f"{self.value}%")

    def __repr__(self):
        return self.value


class BSSType:
    """Base class for BSS Type"""

    def __init__(self, bss_entry):
        self.value = WLAN_API.DOT11_BSS_TYPE_DICT[bss_entry.dot11BssType]
        self.header = Header("TYPE")
        self.subheader = SubHeader("")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class PHYType:
    """Base class for PHY Type"""

    def __init__(self, bss_entry):
        self.value = WLAN_API.DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.header = Header("PHY")
        self.subheader = SubHeader(".11")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.amendment)

    @property
    def generation(self):
        """Get the WFA Generation"""
        return self.get_wfa_generation()

    @property
    def amendment(self):
        """Get the 802.11 amendment"""
        return self.get_amendment()

    @property
    def name(self):
        """Get the current name"""
        return self.value

    @name.setter
    def name(self, value):
        self.value = value

    def get_amendment(self):
        if self.value == "HE":
            return "ax"
        if self.value == "VHT":
            return "ac"
        if self.value == "HT":
            return "n"
        if self.value == "ERP":
            return "g"
        if self.value.replace("-", "") == "HRDSSS":
            return "b"
        if self.value == "OFDM":
            return "a"
        return ""

    def get_wfa_generation(self):
        """
        https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-6
        """
        if self.value == "HE":
            return "6"
        if self.value == "VHT":
            return "5"
        if self.value == "HT":
            return "4"
        if self.value == "ERP":
            return "3"
        if self.value.replace("-", "") == "HRDSSS":
            return "2"
        if self.value == "OFDM":
            return "1"
        return "-"

    def __repr__(self):
        return self.value


class Capabilities:
    """Base class for Capabilities"""

    def __init__(self, bss_entry):
        self.value = bss_entry.CapabilityInformation
        self.ci = WLAN_API.CapabilityInformation()
        self.ci.asbyte = self.value
        self.hex = hex(self.value)
        self.ess = self.ci.bits.ESS
        self.ibss = self.ci.bits.IBSS
        self.cf_pollable = self.ci.bits.CF_POLLABLE
        self.cf_poll_request = self.ci.bits.CF_POLL_REQUEST
        self.privacy = self.ci.bits.PRIVACY
        self.short_preamble = self.ci.bits.SHORT_PREAMBLE
        self.pbcc = self.ci.bits.PBCC
        self.channel_agility = self.ci.bits.CHANNEL_AGILITY
        self.spectrum_management = self.ci.bits.SPECTRUM_MANAGEMENT
        self.qos = self.ci.bits.QOS
        self.short_slot_time = self.ci.bits.SHORT_SLOT_TIME
        self.automatic_power_save_delivery = self.ci.bits.APSD
        self.radio_measurement = self.ci.bits.RADIO_MEASUREMENT
        self.dsss_ofdm = self.ci.bits.DSSS_OFDM
        self.delayed_block_ack = self.ci.bits.DELAYED_BLOCK_ACK
        self.immediate_block_ack = self.ci.bits.IMMEDIATE_BLOCK_ACK


class ChannelFrequency:
    """Base class for Channel Frequency"""

    def __init__(self, bss_entry):
        self.value = str(int(bss_entry.ChCenterFrequency / 1000))
        self.header = Header("CENT CH")
        self.subheader = SubHeader("FREQ.")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return self.value


class ChannelNumber:
    """Base class for Channel Number"""

    def __init__(self, bss_entry):
        self.frequency = str(bss_entry.ChCenterFrequency)
        self.value = get_channel_number_from_frequency(
            str(int(bss_entry.ChCenterFrequency / 1000))
        )
        self.header = Header("CHANNEL")
        self.subheader = SubHeader("[#@MHz]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __len__(self):
        return len(self.value)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return self.value


class ChannelWidth:
    """Base class for Channel Width"""

    def __init__(self):
        self.value = "20"
        self.header = Header("WIDTH")
        self.subheader = SubHeader("[MHz]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class SpatialStreams:
    """Base class for Spatial Streams"""

    def __init__(self):
        self.value = 1
        self.header = Header("SS")
        self.subheader = SubHeader("#")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class Uptime:
    """Base class for uptime"""

    def __init__(self, value):
        self.value = value
        self.header = Header("AP UPTIME")
        self.subheader = SubHeader("[approx.]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class QBSSStations:
    """Base class for QBSS Station Count"""

    def __init__(self):
        self.value = ""
        self.header = Header("STA")
        self.subheader = SubHeader("CNT")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class BSSColor:
    """Base class for BSS Color"""

    def __init__(self):
        self.value = ""
        self.header = Header("BSS")
        self.subheader = SubHeader("COLOR")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class Utilization:
    """Base class for QBSS Utilization"""

    def __init__(self):
        self.value = ""
        self.header = Header("CHNL")
        self.subheader = SubHeader("UTIL")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)


class BeaconInterval:
    """Base class for Beacon Interval"""

    def __init__(self, value):
        self.value = self.get_beacon_interval(value)
        self.header = Header("BEACON")
        self.subheader = SubHeader("INTVL.")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return f"{self.value}ms"

    def get_beacon_interval(self, beaconperiod):
        """
        Beacons are sent by the AP at a regular interval defined as the Target Beacon Transmission Time (TBTT).

        The TBTT is a time interval measured in time units (TUs). A TU is equal to 1024 microseconds.

        The TU is often confused with 1 ms.

        The reality is seen in the definition of a time unit in the 802.11-2012 standard document, which reads, "A measurement of time equal to 1024 µs."
        """
        return (1024 * beaconperiod) / 1000


class Security:
    """Base class for Security"""

    def __init__(self, capabilities):
        if capabilities.ci.bits.PRIVACY == 1:
            self.value = "WEP"
        else:
            self.value = "NONE"
        self.header = Header("SECURITY", Alignment.LEFT)
        self.subheader = SubHeader("[auth/unicast/group]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __str__(self):
        return str(self.value)

    def __format__(self, fmt):
        return f"{self.value:{fmt}}"

    def __len__(self):
        return len(self.value)


class InformationElement:
    """Base class for Information Elements"""

    def __init__(
        self,
        element,
        element_id,
        element_id_extension=None,
        extensible=None,
        fragmentable=None,
    ):
        self.element = element
        self.element_id = element_id
        self.element_id_extension = element_id_extension
        self.extensible = extensible
        self.fragmentable = fragmentable


class CountryElement(InformationElement):
    """Base class for 802.11-2016 9.4.2.9 Country Element"""

    pass


class MobilityDomain(InformationElement):
    FT_CAPABILITY_AND_POLICY = ""

    class MobilityDomainIdentifier:
        FAST_BSS_TRANSITION_OVER_DS = ""
        RESOURCE_REQUEST_PROTOCOL_CAPABILITY = ""
        RESERVED = ""

    def __init__(self):
        self.MobilityDomainIdentifier.FAST_BSS_TRANSITION_OVER_DS = ""
        self.MobilityDomainIdentifier.RESOURCE_REQUEST_PROTOCOL_CAPABILITY = ""
        self.MobilityDomainIdentifier.RESERVED = ""
        self.FT_CAPABILITY_AND_POLICY = ""


class DOT11w(InformationElement):
    def __init__(self):
        self.required = ""
        self.optional = ""
        self.none = ""
        super().__init__(self)


class HEOperation(InformationElement):
    @dataclass
    class _HEOperationParameters:
        DefaultPEDuration: int
        TWTRequired: bool
        TXOPDurationRTSThreshold: int
        VHTOperationInformationPresent: bool
        ERSUDisable: bool
        Reserved: int

    @dataclass
    class _BSSColorInformation:
        BSSColor: int
        PartialBSSColor: bool
        BSSColorDisabled: bool

    @dataclass
    class _BasicHEMCSAndNSSSet:
        MaxHEMCSFor1SS: int
        MaxHEMCSFor2SS: int
        MaxHEMCSFor3SS: int
        MaxHEMCSFor4SS: int
        MaxHEMCSFor5SS: int
        MaxHEMCSFor61SS: int
        MaxHEMCSFor7SS: int
        MaxHEMCSFor8SS: int

    def __init__(self):
        self.HEOperationParameters = self._HEOperationParameters
        self.BSSColorInformation = self._BSSColorInformation
        self.BasicHEMCSAndNSSSet = self._BasicHEMCSAndNSSSet
        self.VHTOperationElement = None
        self.MaxCohostedBSSIDIndicator = None
        self.SixGHzOperationInformation = None
        super().__init__(self)


class Amendments(collections.abc.MutableSequence):
    def __init__(self, *args):
        self.list = list()
        self.extend(list(args))
        self.header = Header("AMENDMENTS")
        self.subheader = SubHeader("[802.11]")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __delitem__(self, index):
        del self.list[index]

    def __getitem__(self, index):
        return self.list[index]

    def __len__(self):
        return len("/".join(sorted(self.list)))

    def __setitem__(self, index, value):
        self.list[index] = value

    def insert(self, index, value):
        self.list.insert(index, value)

    def __str__(self):
        return "/".join(sorted(self.list))

    def __format__(self, fmt):
        return format("/".join(sorted(self.list)), fmt)


class IENumbers(collections.abc.MutableSequence):
    def __init__(self, *args):
        self.list = list()
        self.extend(list(args))
        self.header = Header("IEs")
        self.subheader = SubHeader("")

    def out(self):
        return OUT_TUPLE(self.__str__(), self.header, self.subheader)

    def __delitem__(self, index):
        del self.list[index]

    def __getitem__(self, index):
        return self.list[index]

    def __len__(self):
        return len("/".join(sorted(self.list)))

    def __setitem__(self, index, value):
        self.list[index] = value

    def insert(self, index, value):
        self.list.insert(index, value)

    def __str__(self):
        return "/".join(sorted(self.list))

    def __format__(self, fmt):
        return format("/".join(sorted(self.list)), fmt)


class WirelessNetworkBss:
    def __init__(self, bss_entry, connected_bssid=None):
        """
        bss_entry:
        ("dot11Ssid", Dot11SSID),
        ("PhyId", c_ulong),
        ("dot11Bssid", DOT11_MAC_ADDRESS),
        ("dot11BssType", DOT11_BSS_TYPE),
        ("dot11BssPhyType", DOT11_PHY_TYPE),
        ("Rssi", c_long),
        ("LinkQuality", c_ulong),
        ("InRegDomain", c_bool),
        ("BeaconPeriod", c_ushort),
        ("Timestamp", c_ulonglong),
        ("HostTimestamp", c_ulonglong),
        ("CapabilityInformation", c_ushort),
        ("ChCenterFrequency", c_ulong),
        ("WlanRateSet", WLANRateSet),
        ("IeOffset", c_ulong),
        ("IeSize", c_ulong),
        :param bss_entry:
        """
        # init values before parsing IEs
        self.ssid = SSID(bss_entry)
        self.bssid = BSSID(bss_entry, connected_bssid)
        self.phy_id = bss_entry.PhyId
        self.bss_type = BSSType(bss_entry)
        self.phy_type = PHYType(bss_entry)
        self.rssi = RSSI(bss_entry.Rssi)
        self.signal_quality = SignalQuality(bss_entry.LinkQuality)
        self.has_country_code = bss_entry.InRegDomain
        self.timestamp = bss_entry.Timestamp
        self.host_timestamp = bss_entry.HostTimestamp
        self.uptime = Uptime(self.convert_timestamp_to_uptime(self.timestamp))
        self.beacon_interval = BeaconInterval(bss_entry.BeaconPeriod)
        self.channel_number = ChannelNumber(bss_entry)
        self.channel_frequency = ChannelFrequency(bss_entry)
        self.channel_width = ChannelWidth()
        self.channel_number_marked = self.channel_number
        self.wlanrateset = Rates(bss_entry)
        self.ie_rates = IERates()
        self.capabilities = Capabilities(bss_entry)
        self.ie_size = bss_entry.IeSize
        self.country_code = "--"
        self.apname = APName()
        self.security = Security(self.capabilities)
        self.spatial_streams = SpatialStreams()
        self.stations = QBSSStations()
        self.utilization = Utilization()
        self.ienumbers = IENumbers()
        self.amendments = Amendments()
        self.modes = []
        self.bssbytes = bss_entry
        self.bsscolor = BSSColor()
        self.channel_marking = ""
        self.channel_list = self.channel_number.value
        self.dtim = DTIM()
        self.voice_acm = ACM("VO")
        self.video_acm = ACM("VI")
        self.besteffort_acm = ACM("BE")
        self.background_acm = ACM("BK")

        # parse IEs
        self.raw_information_elements = self._get_information_elements_buffer(bss_entry)
        self.iesbytes = bytearray(self.raw_information_elements)
        # self.iesbytes = [c for c in self.raw_information_elements]
        self.information_elements = WirelessNetworkBss._process_information_elements(
            self, bss_entry
        )

        # do stuff now that IEs have been parsed

        # if self.dtim.value:
        #    print(f"dtim {self.dtim.value} present for {self.bssid}")
        # else:
        #    print(f"dtim not present for {self.bssid}")
        self.ie_rates.value = self.parse_rates(self.ie_rates)
        if len(self.channel_number) == 1:
            self.channel_number = f"  {self.channel_number}"
        if len(self.channel_number) == 2:
            self.channel_number = f" {self.channel_number}"
        # if len(self.channel_number) == 3:
        #    pass
        self.channel_number_marked.value = (
            f"{self.channel_number}@{self.channel_width}{self.channel_marking}"
        )

    @staticmethod
    def convert_timestamp_to_uptime(timestamp) -> str:
        """
        converts timestamp field from the 802.11 beacon or probe response frame to a
        human readable format. This frame is received by the WLAN interface.

        :param timestamp: unix integer representing an uptime timestamp
        :return: human readable uptime string
        """
        timestamp = timedelta(microseconds=timestamp)
        timestamp = timestamp - timedelta(microseconds=timestamp.microseconds)
        return (
            f"{str(timestamp.days).strip().zfill(2)}d "
            f"{str(timestamp).rpartition(',')[2].strip()}"
        )

    @staticmethod
    def parse_rates(ie_rates) -> str:
        """
        takes a list of rates including basic rates, and orders them.

        :param ie_rates: list of unordered rates
        :return: str of ordered rates
        """
        if len(ie_rates.value) > 0:
            ie_rates.value = ie_rates.value.replace("(b)", "*")
            basics = []
            supported = []
            list = ie_rates.value.strip().split(" ")
            for rate in list:
                if "*" in rate:
                    rate = rate.replace("*", "")
                    basics.append(float(rate) if "." in rate else int(rate))
                else:
                    supported.append(float(rate) if "." in rate else int(rate))
            rates = basics + supported
            rates.sort(key=float)
            rates = [str(s) for s in rates]
            basics = [str(s) for s in basics]
            for index, value in enumerate(rates):
                if value in basics:
                    rates[index] = f"{value}*"
            return " ".join(rates)
        else:
            return []

    @staticmethod
    def printoutlist(outlist):
        outstring = ""
        index = 0
        for i in outlist[0]:
            max_len = max(len(str(x)) for x in [y[index] for y in outlist])
            outstring += "{{{}:{}}}  ".format(index, max_len)
            index += 1

        for i in outlist:
            print(outstring.format(*tuple(i)))

    def __str__(self):
        outlist = []
        outlist.append(
            [
                "SSID",
                "BSSID",
                "RSSI",
                "TYPE",
                "AMEND.",
                "PHY",
                "SECURITY",
                "CTRY.",
                "BEACON",
                "UPTIME",
            ]
        )
        outlist.append(
            [
                self.ssid.value,
                self.bssid.value,
                f"{self.rssi} dBm",
                self.bss_type.value,
                self.phy_type.amendment,
                self.phy_type.name,
                self.security.value,
                self.country_code,
                f"{self.beacon_interval.value}ms",
                self.uptime.value,
            ]
        )
        self.printoutlist(outlist)
        print("")
        outlist = []  # TODO: revisit
        outlist.append(["CHANNEL", "WIDTH", "FREQ.", "AMENDMENTS", "SS"])
        outlist.append(
            [
                f"[{self.channel_list}]",
                f"{self.channel_width.value} MHz",
                self.channel_frequency.value,
                f"{self.amendments}",
                f"{self.spatial_streams}",
            ]
        )
        self.printoutlist(outlist)

        out = ""
        out += "<hr>\n"
        out += "Capabilities: {}\n".format(self.capabilities.hex)
        out += (
            ".... .... .... ...{} ESS capabilities\n".format(self.capabilities.ess)
            if self.capabilities.ess
            else ""
        )
        out += (
            ".... .... .... ..{}. IBSS status\n".format(self.capabilities.ibss)
            if self.capabilities.ibss
            else ""
        )
        out += (
            ".... .... .... .{}.. CF pollable\n".format(self.capabilities.cf_pollable)
            if self.capabilities.cf_pollable
            else ""
        )
        out += (
            ".... .... .... {}... CF pollable\n".format(self.capabilities.cf_pollable)
            if self.capabilities.cf_pollable
            else ""
        )
        out += (
            ".... .... ...{} .... Privacy\n".format(self.capabilities.privacy)
            if self.capabilities.privacy
            else ""
        )
        out += (
            ".... .... ..{}. .... Short Preamble\n".format(
                self.capabilities.short_preamble
            )
            if self.capabilities.short_preamble
            else ""
        )
        out += (
            ".... .... .{}.. .... PBCC\n".format(self.capabilities.pbcc)
            if self.capabilities.pbcc
            else ""
        )
        out += (
            ".... .... {}... .... Channel Agility\n".format(
                self.capabilities.channel_agility
            )
            if self.capabilities.channel_agility
            else ""
        )
        out += (
            ".... ...{} .... .... Spectrum Management\n".format(
                self.capabilities.spectrum_management
            )
            if self.capabilities.spectrum_management
            else ""
        )
        out += (
            ".... ..{}. .... .... QoS\n".format(self.capabilities.qos)
            if self.capabilities.qos
            else ""
        )
        out += (
            ".... .{}.. .... .... Short Slot Time\n".format(
                self.capabilities.short_slot_time
            )
            if self.capabilities.short_slot_time
            else ""
        )
        out += (
            ".... {}... .... .... Automatic Power Save Delievery (APSD) \n".format(
                self.capabilities.automatic_power_save_delivery
            )
            if self.capabilities.automatic_power_save_delivery
            else ""
        )
        out += (
            "...{} .... .... .... Radio Measurement\n".format(
                self.capabilities.radio_measurement
            )
            if self.capabilities.radio_measurement
            else ""
        )
        out += (
            "..{}. .... .... .... DSSS-OFDM\n".format(self.capabilities.dsss_ofdm)
            if self.capabilities.dsss_ofdm
            else ""
        )
        out += (
            ".{}.. .... .... .... Delayed Block Ack\n".format(
                self.capabilities.delayed_block_ack
            )
            if self.capabilities.delayed_block_ack
            else ""
        )
        out += (
            "{}... .... .... .... Immediate Block Ack\n".format(
                self.capabilities.immediate_block_ack
            )
            if self.capabilities.immediate_block_ack
            else ""
        )
        # out += "Raw: {}".format(self.raw_information_elements)
        out += "<hr>\n"
        # out += f"{len(self.ienumbers.list)} INFORMATION ELEMENTS ({self.ie_size} bytes):\n"
        eid_len = get_attr_max_len(self.information_elements, "eid")
        length_len = get_attr_max_len(self.information_elements, "length")
        names_len = get_attr_max_len(self.information_elements, "name")
        decoded_len = get_attr_max_len(self.information_elements, "decoded")
        if decoded_len < len("DECODED"):
            decoded_len = len("DECODED")
        if length_len < len("SIZE"):
            length_len = len("SIZE")
        # pbody_len = get_attr_max_len(self.information_elements, "pbody")
        out += "{0:<{length_len}}  {1:<{eid_len}}  {2:<{names_len}}  {3:<{decoded_len}}\n".format(
            "SIZE",
            "ID",
            f"{len(self.ienumbers.list)} ELEMENTS ({self.ie_size} bytes)",
            "DECODED",
            length_len=length_len,
            eid_len=eid_len,
            names_len=names_len,
            decoded_len=decoded_len,
        )
        for ie in self.information_elements:
            out += "{0:<{length_len}}  {1:<{eid_len}}  {2:<{names_len}}  {3:<{decoded_len}}\n".format(
                ie.length,
                ie.eid,
                ie.name,
                ie.decoded,  # ie.pbody and ie.body
                length_len=length_len,
                eid_len=eid_len,
                names_len=names_len,
                decoded_len=decoded_len,
            )
        # out += "{0:<{names_len}}  {1:<{decoded_len}}\n".format(
        #    "INFORMATION ELEMENT",
        #    "DECODED",
        #    names_len=names_len,
        #    decoded_len=decoded_len,
        # )

        # for ie in self.information_elements:
        #    out += "{0:<{names_len}}  {1:<{decoded_len}}\n".format(
        #        ie.name,
        #        ie.decoded,
        #        names_len=names_len,
        #        decoded_len=decoded_len,
        #    )
        return out

    def _get_information_elements_buffer(self, bss_entry):
        """
        gets the buffer containing the information elements bytes
        """
        out = ""
        bss_entry_pointer = addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = c_char * bss_entry.IeSize
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        return ie_buffer
        # for byte in ie_buffer:
        #    out += str(byte)
        # return out

    def _append_information_elements(
        self, element_id, element_length, element_data, information_elements
    ):
        # we're working with a new information element
        parsed_ie = WirelessNetworkBss._parse_information_element(
            self, element_id, element_length, element_data
        )
        if parsed_ie.length == 1:
            parsed_ie_length = f"{parsed_ie.length} byte"
        else:
            parsed_ie_length = f"{parsed_ie.length} bytes"
        # handle pretty printing decoded strings
        if parsed_ie:
            decoded_list = parsed_ie.decoded.splitlines()  # split("\n")
            if len(decoded_list) > 1:
                for index, information_element in enumerate(decoded_list):
                    if index == 0:
                        information_elements.append(
                            WLAN_API.InformationElement(
                                parsed_ie.eid,
                                parsed_ie.name,
                                parsed_ie.length,
                                information_element,
                                parsed_ie.body,
                                f"{parsed_ie.pbody} ({parsed_ie_length})",
                            )
                        )
                    else:
                        information_elements.append(
                            WLAN_API.InformationElement(
                                "", "", "", information_element, "", ""
                            )
                        )
            else:
                information_elements.append(
                    WLAN_API.InformationElement(
                        parsed_ie.eid,
                        parsed_ie.name,
                        parsed_ie.length,
                        parsed_ie.decoded,
                        parsed_ie.body,
                        f"{parsed_ie.pbody} ({parsed_ie_length})",
                    )
                )

    def _process_information_elements(self, bss_entry):
        # ctypes
        bss_entry_pointer = addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = c_char * bss_entry.IeSize
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        information_elements = []
        # init element vars
        element_id = 0
        element_length = 0
        element_data = b""
        # loop tracking vars
        is_index_byte = True
        is_length_byte = True
        index = 0
        for byte, last in flag_last_object(ie_buffer):
            if is_index_byte:
                element_id = bytes_to_int(byte)
                is_index_byte = False
                continue
            if is_length_byte:
                element_length = bytes_to_int(byte)
                is_length_byte = False
                continue
            if index < element_length:
                index += 1
                element_data = element_data + byte
            else:
                self._append_information_elements(
                    element_id, element_length, element_data, information_elements
                )
                # reset vars to decode next information element
                index = 0
                is_index_byte = True
                is_length_byte = True
                element_data = b""
                element_id = 0
                element_length = 0
                # current byte should be next index byte
                element_id = bytes_to_int(byte)
                is_index_byte = False
                continue
            if last:
                self._append_information_elements(
                    element_id, element_length, element_data, information_elements
                )
        return information_elements

    def decode_bytefile_ies(bytes):
        # init element vars
        information_elements = []
        eid = 0
        elength = 0
        edata = b""
        # loop tracking vars
        is_index_byte = True
        is_length_byte = True
        count = 0
        for byte, last in flag_last_object(bytes):
            if is_index_byte:
                eid = byte
                is_index_byte = False
                continue
            if is_length_byte:
                elength = byte
                is_length_byte = False
                continue
            if count < elength:
                count = count + 1
                if int_to_bytes(byte) == b"":
                    edata = edata + b"\x00"
                else:
                    edata = edata + int_to_bytes(byte)
            else:
                # we're working with a new information element
                # print("{} {} {}".format(eid, elength, edata))

                # we're working with a new information element
                # passing in None where we would usually pass in self.
                parsed_ie = WirelessNetworkBss._parse_information_element(
                    None, eid, elength, edata
                )
                str_len = f"{parsed_ie.length} bytes"
                # handle pretty printing decoded strings
                if parsed_ie:
                    decoded_list = parsed_ie.decoded.split("\n")
                    if len(decoded_list) > 1:
                        for count, item in enumerate(decoded_list):
                            if count == 0:
                                information_elements.append(
                                    WLAN_API.InformationElement(
                                        parsed_ie.eid,
                                        parsed_ie.name,
                                        str_len,
                                        item,
                                        parsed_ie.body,
                                        parsed_ie.pbody,
                                    )
                                )
                            else:
                                information_elements.append(
                                    WLAN_API.InformationElement(
                                        "", "", "", item, "", ""
                                    )
                                )
                    else:
                        information_elements.append(
                            WLAN_API.InformationElement(
                                parsed_ie.eid,
                                parsed_ie.name,
                                str_len,
                                parsed_ie.decoded,
                                parsed_ie.body,
                                parsed_ie.pbody,
                            )
                        )
                # reset vars for next information element
                count = 0
                is_index_byte = True
                is_length_byte = True
                edata = b""
                eid = 0
                elength = 0
                # current byte should be next index byte
                eid = byte
                is_index_byte = False
                continue
            if last:
                # passing in None where we would usually pass in self.
                information_elements.append(
                    WirelessNetworkBss._parse_information_element(
                        None, eid, elength, edata
                    )
                )
        return information_elements

    @staticmethod
    def get_eid_name(eid):
        """
        gets and returns name of element based on id
        """
        name = ""
        try:
            name = IE_DICT[eid]
        except KeyError:
            name = "Undecoded"
        return name

    @staticmethod
    def _parse_information_element(self, element_id, element_length, element_data):
        if self is not None:
            if element_id == 5:
                self.ienumbers.append(f"{element_id}*")
            else:
                self.ienumbers.append(str(element_id))
        # 802.11-2016 9.4.2.2 SSID element
        if element_id == 0:
            decoded = WirelessNetworkBss.__parse_ssid_element(element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.3 Supported Rates
        if element_id == 1:
            decoded = WirelessNetworkBss.__parse_rates(element_data)
            if self:
                self.ie_rates.value = decoded
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                f"{', '.join([rate.strip() for rate in decoded.strip().split(' ')])} Mbit/s",
                # decoded.strip(),
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.4 DSSS Parameter Set element
        if element_id == 3:
            decoded = WirelessNetworkBss.__parse_dsss_parameter_set_element(
                element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.6 TIM Element
        if element_id == 5:
            decoded = WirelessNetworkBss.__parse_tim_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        if element_id == 7:
            decoded = WirelessNetworkBss._parse_country_information_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.28 BSS Load element (QBSS) (11)
        if element_id == 11:
            decoded = WirelessNetworkBss._parse_bss_load_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.14 Power Constraint (32)
        if element_id == 32:
            decoded = WirelessNetworkBss._parse_power_constraint_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.17 TPC Report Element: Transmit Power (35)
        if element_id == 35:
            decoded = WirelessNetworkBss._parse_tpc_report_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.23 Quiet Element: (40)
        if element_id == 40:
            decoded = WirelessNetworkBss._parse_quiet_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.12 ERP element: (42)
        if element_id == 42:
            decoded = WirelessNetworkBss._parse_erp_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.56 HT Capabilities (45)
        if element_id == 45:
            decoded = WirelessNetworkBss._parse_ht_capabilities_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.25 RSNE: RSN Information (48)
        if element_id == 48:
            decoded = WirelessNetworkBss._parse_rsn_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.13 Extended Supported Rates
        if element_id == 50:
            decoded = WirelessNetworkBss.__parse_rates(element_data)
            if self:
                self.ie_rates.value += decoded
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                f"{', '.join([rate.strip() for rate in decoded.strip().split(' ')])} Mbit/s",
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 AP Channel Report element (51)
        if element_id == 51:
            decoded = WirelessNetworkBss._parse_ap_channel_report_element(
                element_data, element_length
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.47 Mobility Domain element (MDE)
        if element_id == 54:
            decoded = WirelessNetworkBss._parse_mobility_domain_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.57 HT Operation element: HT Information (61)
        if element_id == 61:
            decoded = WirelessNetworkBss._parse_ht_operation_element(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.45 RM Enabled Capabilities element (70)
        if element_id == 70:
            decoded = WirelessNetworkBss._parse_rm_enabled_capabilities_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.59 Overlapping BSS Scan Parameters (74)
        if element_id == 74:
            decoded = WirelessNetworkBss._parse_overlapping_bss_scan_parameters_element(
                element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # interworking (Hotspot 2.0) TODO
        if element_id == 107:
            decoded = WirelessNetworkBss._parse_interworking_hotspot_two_point_zero(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.98 Mesh Configuration element (113)
        if element_id == 113:
            decoded = WirelessNetworkBss._parse_mesh_configuration(self, element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.27 Extended Capabilities element (127)
        if element_id == 127:
            decoded = WirelessNetworkBss._parse_extended_capabilities(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.26 Vendor Specific element - Symbol Proprietary (173)
        if element_id == 173:
            decoded = WirelessNetworkBss._parse_symbol_proprietary(element_data)
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.158.2 VHT Capabilities (191)
        if element_id == 191:
            decoded = WirelessNetworkBss._parse_vht_capabilities_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 VHT Operation (192)
        if element_id == 192:
            decoded = WirelessNetworkBss._parse_vht_operation_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        if element_id == 133:
            decoded = WirelessNetworkBss._parse_cisco_ccx1_ckip_device_name(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 9.4.2.26 Vendor Specific element (221)
        if element_id == 221:
            decoded = WirelessNetworkBss._parse_vendor_specific_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        # 802.11-2016 Element ID Extension field (255)
        if element_id == 255:
            ext_name, decoded = WirelessNetworkBss._parse_extension_tag_element(
                self, element_data
            )
            return WLAN_API.InformationElement(
                element_id,
                WirelessNetworkBss.get_eid_name(element_id) + ": {}".format(ext_name),
                element_length,
                decoded,
                element_data,
                format_bytes_as_hex(element_data),
            )

        return WLAN_API.InformationElement(
            element_id,
            WirelessNetworkBss.get_eid_name(element_id),
            element_length,
            "Parser not implemented. Contact developer if you want this supported.",
            element_data,
            format_bytes_as_hex(element_data),
        )

    def _parse_mobility_domain_element(self, element_data):
        if self is not None:
            self.amendments.append("r")
        return ""

    def _parse_rm_enabled_capabilities_element(self, element_data):
        if self is not None:
            self.amendments.append("k")
        return ""

    def _parse_extended_capabilities(self, element_data):
        out = ""
        body = list(memoryview(element_data))
        out = f"0x{element_data.hex()}"
        if len(body) > 1:
            if get_bit(body[2], 3):  # octet 3, bit 4 ... (or bit 19 for BSS Transition)
                if self is not None:
                    self.amendments.append("v")
        return out

    def _parse_symbol_proprietary(element_data):
        body = list(memoryview(element_data))
        zero, one, two = [body[i] for i in [0, 1, 2]]  # list comprehension
        mac = convert_mac_address_to_string([zero, one, two])
        sub_body = [element_data[i : i + 1] for i in range(len(element_data))]
        out = ""
        # https://github.com/wireshark/wireshark/commit/44129c6ded87914461d48190918fb2b29dd93105
        if len(body) < 3:
            return f"length {len(body)} wrong must be >= 3"

        assoc_clients = int(body[3] + body[4])
        load_kbps = int.from_bytes(sub_body[5] + sub_body[6], "little")
        load_pps = int.from_bytes(sub_body[7] + sub_body[8], "little")
        client_txpower = int(body[9] + body[10])
        timestamp = ""  # this is 4 bytes following the previous
        out += f"Associated Clients {assoc_clients}, Load {load_kbps} Kbps, Load {load_pps} pkt/s"
        out += f"\nDesired Client Tx Power: {client_txpower}, Timestamp (developer did not do this yet)"
        if mac == "00:a0:f8":  # Zebra Technologies
            # TODO: come back and reorg this code
            pass

        return out

    def _parse_cisco_ccx1_ckip_device_name(self, element_data):
        body = list(memoryview(element_data))
        clients = body[26]
        apname = body[10:]
        apname = "".join([chr(i) for i in apname[:-5]])
        if self is not None:
            self.apname.value = apname
        return f"AP Name: {apname}, Clients: {clients}"

    @staticmethod
    def _parse_vendor_specific_element(self, element_data):
        """
        the IEEE has assigned organizationally unique IDs both of 24-bit length (OUI and CID)
        and longer length. In the latter case specific OUI values are shared over
        multiple organizations, e.g., using 36-bit length identifiers (OUI-36)
        (see IEEE Registration Authority [B19], [B20]).

        the length of the Organization Identifier field (j) is the minimum number of octets
        required to contain the entire organizationally unique identifier,
        and the first 3 octets contain the OUI or CID portion of the identifier.

        thus, the Organization Identifier field is 3 octets in length if the organizationally
        unique identifier is an OUI, or 5 octets in length if the organizationally unique
        identifier is an OUI-36.

        field: element id | length | organization identifier | vendor specific content
        octet: 1          | 1      | j                       | variable

        if the length of the organizationally unique identifier is not an integer number of octets,
         the least significant bits of the last octet are specified by the organization identified.

        notE—For example, for the organizationally unique identifier 0x0050C24A4,
        the Organization Identifier field would contain 0x0050C24A4y where y represents the
        four least significant bits of the fifth octet of the field.

        the value of y is specified by the organization whose identifier is 0x0050C24A4.
        """
        log = logging.getLogger(__name__)
        memoryview_body = list(memoryview(element_data))
        zero, one, two, three = [
            memoryview_body[i] for i in [0, 1, 2, 3]
        ]  # list comprehension
        oui = convert_mac_address_to_string([zero, one, two, three])
        element_body = [element_data[i : i + 1] for i in range(len(element_data))]
        # oui_type = b""
        oui_type = int.from_bytes(element_body[3], "little")
        out = ""
        apname = ""
        if "08:00:09" in oui:
            out = "Hewlett Packard"
        if "8c:fd:f0" in oui:
            out = f"OUI: {oui} (Qualcomm Inc.), Subtype: {oui_type}"
        if "00:13:92" in oui:
            out = "Ruckus Wireless"
        if "00:26:86" in oui:
            out = "Quantenna Communications, Inc."
        if "00:e0:4c" in oui:
            out = "Realtek Semiconductor Corp."
        if "50:6f:9a:0a" in oui:
            out = "Wi-Fi Alliance"
        if "50:6f:9a:09" in oui:  # Wi-Fi Alliance P2P
            out = "Wi-Fi Alliance P2P"
        if "00:0b:86" in oui:  # Aruba
            if oui_type == 1:
                oui_subtype = int.from_bytes(element_body[4], "little")
                if oui_subtype == 3:  # AP Name
                    offset = element_body[5]
                    apname = "".join([chr(i) for i in memoryview_body[6:]])
                    # EID 221 (len=20): OUI: 00:0b:86 Subtype: 1 Data b'\x00\x0b\x86\x01\x03\x00Josh_Schmelzle'
                    out = "OUI: {} (Aruba), Subtype: {}, AP Name: {}".format(
                        oui, oui_type, apname
                    )
                    if self is not None:
                        self.apname.value = apname
                        # log.debug(f"(aruba device name) {apname}")
        if "00:a0:f8" in oui:  # Zebra Technologies
            # EID 221 (len=18): OUI: 00:a0:f8 Subtype: 1 Data b'\x00\xa0\xf8\x01\x03\x01\x0f\xc0\x00\x00\x00\x06ap8533'
            if oui_type == 1:  # AP name
                # offset = element_body[4, 5, 6, 7, 8, 9, 10] #offset is 7 then + 1 for ap length
                length = element_body[11]
                apname = "".join([chr(i) for i in memoryview_body[12:]])
                out = "OUI: {} (Extreme (Zebra)), Subtype: {}, AP Name: {}".format(
                    oui, oui_type, apname
                )
                if self is not None:
                    self.apname.value = apname
        if "5c:5b:35:01" in oui:  # Mist
            apname = "".join([chr(i) for i in memoryview_body[4:]])
            out = (
                f"OUI: {oui} (Mist), Subtype: {memoryview_body[:1]}, AP Name: {apname}"
            )
            if self is not None:
                self.apname.value = apname
        if "00:40:96" in oui:  # Cisco
            if oui_type == 0:
                out = "Cisco Aironet (0)"
            if oui_type == 1:
                out = "Cisco Aironet (1)"
            if oui_type == 3:
                out = "Cisco Aironet (3)"
            if oui_type == 11:
                out = "Cisco Aironet (11)"
            if oui_type == 20:
                out = "Cisco Aironet (20)"
        if "00:0b:86" in oui:
            out = f"OUI: {oui} (Aruba, a HPE Company)"
        if "00:16:32" in oui:  # Samsung
            out = "Samsung"
        if "00:10:18" in oui:  # Broadcom
            out = "Broadcom"
        if "00:90:4c" in oui:  # Epigram
            out = "Epigram"
        if "00:03:7f" in oui:  # Atheros
            out = "Atheros"
        if "00:15:6d" in oui:  # Ubiquiti
            out = "Ubiquiti"
        if "00:50:f2:04" in oui:  # Device name here
            out = "Microsoft WPS"
            """
            Access Points must provide the Wi-Fi Protected Setup IE in all beacon and probe-response frames.
            Stations may provide the Wi-Fi Protected Setup IE in all probe-request frames
           
            Page 50 of spec:
            ----------------
            
            Wi-fi Protected Setup encodes information as attributes in a binary type identifier,
            length and value (TLV) format.
           
            The TLV format uses fields as defined in the TLV Format Table.
            TLVs are transmitted and/or saved in big endian byte order.
            
            The overall size occupied by each attribute will include an additional 4 bytes. 
            
            - 2 bytes for the ID
            - 2 bytes for the length
             
            | Byte Offset | Field Length   | Field Name    | Description                    |
            | ----------- | -------------  | ------------- | ------------------------------ |
            | 0           | 2 Bytes        | AttributeType | Type identifier for attribute  |
            | 2           | 2 Bytes        | DataLength    | Length in bytes of data field  |
            | 4           | 0-0xFFFF bytes | Data          | Attribute data                 |
            
            Most Wi-Fi Protected Setup attributes are simple data structures. Some are nested data structures that 
            contain other TLV attributes.
            
            here are a few:
            
            | Description                | ID (Type) | DataLength |
            | -------------------------- | --------- | ---------- |
            | Version                    | 0x104a    | 2B         |
            | WiFi Protected Setup State | 0x1044    | 2B         |
            | Vendor Extension           | 0x1049    | 2B         |
            | Device Name                | 0x1011    | 2B         |
            | Primary Device Type        | 0x1054    | 2B         |
            | Device Name                | 0x1011    | <= 32B     |
            | Model Number               | 0x1024    | <= 32B     |
            | Model Name                 | 0x1023    | <= 32B     |
            | Serial Number              | 0x1042    | <= 32B     |
            """

            from collections import namedtuple

            WPS_Attribute_Tuple = namedtuple(
                "WPS_Attribute_Tuple", ["desc", "lenbytes"]
            )
            WPS_Attributes = {
                "104a": WPS_Attribute_Tuple(desc="Version", lenbytes="1B (int)"),
                "1044": WPS_Attribute_Tuple(
                    desc="WiFi Protected Setup State", lenbytes="1B"
                ),
                "1049": WPS_Attribute_Tuple(
                    desc="Vendor Extension", lenbytes="<=1024B"
                ),
                "1054": WPS_Attribute_Tuple(desc="Primary Device Type", lenbytes="8B"),
                "103b": WPS_Attribute_Tuple(desc="Response Type", lenbytes="1B"),
                "1041": WPS_Attribute_Tuple(desc="Selected Registrar", lenbytes="Bool"),
                "103c": WPS_Attribute_Tuple(desc="RF Bands", lenbytes="1B"),
                "1011": WPS_Attribute_Tuple(desc="Device Name", lenbytes="<32B"),
                "1047": WPS_Attribute_Tuple(desc="UUID-E", lenbytes="16B"),
                "1057": WPS_Attribute_Tuple(desc="AP Setup Locked", lenbytes="Bool"),
                "1021": WPS_Attribute_Tuple(desc="Manufacturer", lenbytes="<= 64B"),
                "1023": WPS_Attribute_Tuple(desc="Model Name", lenbytes="<= 32B"),
                "1024": WPS_Attribute_Tuple(desc="Model Number", lenbytes="<= 32B"),
                "1012": WPS_Attribute_Tuple(desc="Device Password ID", lenbytes="2B"),
                "1042": WPS_Attribute_Tuple(desc="Serial Number", lenbytes="<= 32B"),
                "1053": WPS_Attribute_Tuple(
                    desc="Selected Registrar Config Methods", lenbytes="2B"
                ),
                "1008": WPS_Attribute_Tuple(desc="Config Methods", lenbytes="2B"),
                "1058": WPS_Attribute_Tuple(
                    desc="Application Extension", lenbytes="<= 512B"
                ),
            }

            @dataclass
            class WPS_Data_Element:
                description: str
                id: str
                length: int
                data: str

            ln = len(memoryview(element_data[4:]))
            element_data_iterator = iter(element_data[4:])

            wps_elements = []

            idx = 0

            def get_next_hex(it: iter):
                return "{:02x}".format(next(it))

            for _ in range(ln):
                attribute_id = ""
                for _ in range(2):  # id is two bytes
                    attribute_id += get_next_hex(element_data_iterator)

                wps_attribute = WPS_Attributes.get(attribute_id, None)

                if wps_attribute is None:
                    out = f"couldn't decode WPS attribute {attribute_id}"
                    print(f"{self.bssid}: couldn't decode WPS attribute {attribute_id}")
                    break

                attribute_length = ""
                for _ in range(2):  # len is two bytes
                    attribute_length += get_next_hex(element_data_iterator)

                attribute_length = int(attribute_length, 16)

                data = ""
                for _ in range(attribute_length):  # data is variable length
                    data += get_next_hex(element_data_iterator)

                # print(f"{attribute_id} {wps_attribute.desc} {bytes.fromhex(data).decode('ISO-8859-1')}")
                if wps_attribute.desc == "Version":
                    """
                    Version specifies the Easy Setup version.
                    The one-byte field is broken into a four-bit major part using the top MSBs and
                    four-bit minor part using the LSBs. As an example, version 3.2 would be 0x32.
                    """
                    out += f"\n  Version: 0x{data}"

                decoded = bytes.fromhex(data).decode("ISO-8859-1")

                if wps_attribute.desc == "Application Extension":
                    out += f"\n  Application Extension parser not implemented. Contact developer if you want this supported."

                if wps_attribute.desc == "Manufacturer":
                    out += f"\n  Manufacturer: {decoded}" if data == 0 else ""

                if wps_attribute.desc == "Model Name":
                    out += f"\n  Model Name: {decoded}" if data == 0 else ""

                if wps_attribute.desc == "Model Number":
                    out += f"\n  Model Number: {decoded}" if data == 0 else ""

                if wps_attribute.desc == "Serial Number":
                    out += f"\n  Serial Number: {decoded}" if data == 0 else ""

                if wps_attribute.desc == "Device Name":
                    apname = bytes.fromhex(data).decode("utf-8")
                    out += f"\n  Device Name: {apname}"
                    if self is not None:
                        self.apname.value = apname

                idx += 4 + attribute_length
                if idx >= ln:
                    break
        if "00:50:f2:11" in oui:
            out = "Microsoft"
        if "00:50:f2:01" in oui:
            out = "Microsoft"
        if (
            "00:50:f2:02" in oui
        ):  # WMM Information Element and # WMM/WME Parameter Element
            if oui_type == 2:
                if self is not None:
                    if "e" not in self.amendments:
                        self.amendments.append("e")
                oui_subtype = int.from_bytes(element_body[4], "little")
                version = int.from_bytes(element_body[5], "little")
                qos = element_body[6]
                if oui_subtype == 0:  # WMM Information Element
                    # print(
                    #    f"oui_subtype 0 under WMM information element for {self.bssid}"
                    # )
                    U_APSD = get_bit(memoryview_body[0], 7)
                    RESERVED = (
                        get_bit(memoryview_body[0], 6)
                        + get_bit(memoryview_body[0], 5)
                        + get_bit(memoryview_body[0], 4)
                    )
                    PARAMETER_SET = (
                        get_bit(memoryview_body[0], 3)
                        + get_bit(memoryview_body[0], 2)
                        + get_bit(memoryview_body[0], 1)
                        + get_bit(memoryview_body[0], 0)
                    )
                    out += "Subtype {}, Version {}, QoS 0x{}\n".format(
                        oui_subtype, version, qos.hex()
                    )
                    U_APSD = int(get_bit(memoryview_body[6], 7))
                    PARAMETER_SET_FIELD0 = int(get_bit(memoryview_body[6], 0))
                    PARAMETER_SET_FIELD1 = int(get_bit(memoryview_body[6], 1))
                    PARAMETER_SET_FIELD2 = int(get_bit(memoryview_body[6], 2))
                    PARAMETER_SET_FIELD3 = int(get_bit(memoryview_body[6], 3))
                    PARAMETER_SET = "0x{}".format(
                        int(
                            "{}{}{}{}".format(
                                PARAMETER_SET_FIELD3,
                                PARAMETER_SET_FIELD2,
                                PARAMETER_SET_FIELD1,
                                PARAMETER_SET_FIELD0,
                            ),
                            2,
                        )
                    )
                    QOS_RESERVED_FIELD4 = int(get_bit(memoryview_body[6], 4))
                    QOS_RESERVED_FIELD5 = int(get_bit(memoryview_body[6], 5))
                    QOS_RESERVED_FIELD6 = int(get_bit(memoryview_body[6], 6))
                    QOS_RESERVED = "0x{}".format(
                        int(
                            "{}{}{}".format(
                                QOS_RESERVED_FIELD6,
                                QOS_RESERVED_FIELD5,
                                QOS_RESERVED_FIELD4,
                            ),
                            2,
                        )
                    )
                    out += "{}... .... U-APSD\n".format(U_APSD)
                    out += ".... {}{}{}{} Parameter Set Count: {}\n".format(
                        PARAMETER_SET_FIELD3,
                        PARAMETER_SET_FIELD2,
                        PARAMETER_SET_FIELD1,
                        PARAMETER_SET_FIELD0,
                        PARAMETER_SET,
                    )
                    out += ".{}{}{} .... Reserved: {}".format(
                        QOS_RESERVED_FIELD6,
                        QOS_RESERVED_FIELD5,
                        QOS_RESERVED_FIELD4,
                        QOS_RESERVED,
                    )
                    if self is not None:
                        pass  # print(f"{self.bssid}({self.ssid.value}): WMM subtype 0 - {memoryview_body}\n{out}")
                if oui_subtype == 1:  # WMM/WME Parameter Element
                    out += "Subtype {}, Version {}, QoS 0x{}\n".format(
                        oui_subtype, version, qos.hex()
                    )
                    U_APSD = get_bit(memoryview_body[6], 7)
                    PARAMETER_SET_FIELD0 = get_bit(memoryview_body[6], 0)
                    PARAMETER_SET_FIELD1 = get_bit(memoryview_body[6], 1)
                    PARAMETER_SET_FIELD2 = get_bit(memoryview_body[6], 2)
                    PARAMETER_SET_FIELD3 = get_bit(memoryview_body[6], 3)
                    PARAMETER_SET = "0x{}".format(
                        int(
                            "{}{}{}{}".format(
                                int(PARAMETER_SET_FIELD3),
                                int(PARAMETER_SET_FIELD2),
                                int(PARAMETER_SET_FIELD1),
                                int(PARAMETER_SET_FIELD0),
                            ),
                            2,
                        )
                    )
                    QOS_RESERVED_FIELD4 = get_bit(memoryview_body[6], 4)
                    QOS_RESERVED_FIELD5 = get_bit(memoryview_body[6], 5)
                    QOS_RESERVED_FIELD6 = get_bit(memoryview_body[6], 6)
                    QOS_RESERVED = "0x{}".format(
                        int(
                            "{}{}{}".format(
                                int(QOS_RESERVED_FIELD6),
                                int(QOS_RESERVED_FIELD5),
                                int(QOS_RESERVED_FIELD4),
                            ),
                            2,
                        )
                    )
                    out += "  {}... .... U-APSD: {}\n".format(
                        int(U_APSD), "Enabled" if U_APSD else "Disabled"
                    )
                    out += "  .... {}{}{}{} Parameter Set Count: {}\n".format(
                        int(PARAMETER_SET_FIELD3),
                        int(PARAMETER_SET_FIELD2),
                        int(PARAMETER_SET_FIELD1),
                        int(PARAMETER_SET_FIELD0),
                        PARAMETER_SET,
                    )
                    out += "  .{}{}{} .... Reserved: {}\n".format(
                        int(QOS_RESERVED_FIELD6),
                        int(QOS_RESERVED_FIELD5),
                        int(QOS_RESERVED_FIELD4),
                        QOS_RESERVED,
                    )
                    RESERVED = int.from_bytes(element_body[7], "little")
                    out += "Reserved: {}".format(hex(RESERVED))

                    def PARSE_AC_PARAMETER(memview_body, element_body):
                        AIFSN_FIELD0 = get_bit(memview_body[0], 0)
                        AIFSN_FIELD1 = get_bit(memview_body[0], 1)
                        AIFSN_FIELD2 = get_bit(memview_body[0], 2)
                        AIFSN_FIELD3 = get_bit(memview_body[0], 3)
                        AIFSN = int(
                            "{}{}{}{}".format(
                                int(AIFSN_FIELD3),
                                int(AIFSN_FIELD2),
                                int(AIFSN_FIELD1),
                                int(AIFSN_FIELD0),
                            ),
                            2,
                        )
                        ACM = get_bit(memview_body[0], 4)
                        ACI_FIELD5 = get_bit(memview_body[0], 5)
                        ACI_FIELD6 = get_bit(memview_body[0], 6)
                        ACI = int("{}{}".format(int(ACI_FIELD6), int(ACI_FIELD5)), 2)

                        def GET_ACI_TO_AC(ACI):
                            if ACI == 0:
                                return ["Best Effort", "BE"]
                            if ACI == 1:
                                return ["Background", "BK"]
                            if ACI == 2:
                                return ["Video", "VI"]
                            if ACI == 3:
                                return ["Voice", "VO"]
                            return ["Unknown", "NA"]

                        ACI_NAME = GET_ACI_TO_AC(ACI)

                        if self is not None:
                            if ACI == 0:
                                self.besteffort_acm.value = int(ACM)
                            if ACI == 1:
                                self.background_acm.value = int(ACM)
                            if ACI == 2:
                                self.video_acm.value = int(ACM)
                            if ACI == 3:
                                self.voice_acm.value = int(ACM)

                        RESERVED = get_bit(memview_body[0], 7)
                        ACI_AIFSN = element_body[0]

                        ECWmin0 = get_bit(memview_body[1], 0)
                        ECWmin1 = get_bit(memview_body[1], 1)
                        ECWmin2 = get_bit(memview_body[1], 2)
                        ECWmin3 = get_bit(memview_body[1], 3)

                        ECWmin = int(
                            "{}{}{}{}".format(
                                int(ECWmin3), int(ECWmin2), int(ECWmin1), int(ECWmin0)
                            ),
                            2,
                        )

                        CWmin = 2 ** ECWmin - 1

                        ECWmax4 = get_bit(memview_body[1], 4)
                        ECWmax5 = get_bit(memview_body[1], 5)
                        ECWmax6 = get_bit(memview_body[1], 6)
                        ECWmax7 = get_bit(memview_body[1], 7)

                        ECWmax = int(
                            "{}{}{}{}".format(
                                int(ECWmax7), int(ECWmax6), int(ECWmax5), int(ECWmax4)
                            ),
                            2,
                        )

                        CWmax = 2 ** ECWmax - 1

                        ECWmin_ECWmax = element_body[1]
                        TXOP_LIMIT = int.from_bytes(
                            element_body[2] + element_body[3], "little"
                        )

                        out = ""
                        out += "\n ACI {} ({}/{}):\n  ACM: {}, AIFSN: {}, ECWmin/ECWmax: {}/{} (CWmin/max {}/{}), TXOP Limit: {}".format(
                            ACI,
                            ACI_NAME[0],
                            ACI_NAME[1],
                            # BE_ACI_AIFSN.hex(),
                            "Enabled" if ACM else "Disabled",
                            AIFSN,
                            ECWmin,
                            ECWmax,
                            CWmin,
                            CWmax,
                            TXOP_LIMIT,
                        )
                        return out

                    out += "\nAC Parameters:"
                    out += PARSE_AC_PARAMETER(memoryview_body[8:], element_body[8:])
                    out += PARSE_AC_PARAMETER(memoryview_body[12:], element_body[12:])
                    out += PARSE_AC_PARAMETER(memoryview_body[16:], element_body[16:])
                    out += PARSE_AC_PARAMETER(memoryview_body[20:], element_body[20:])
                if oui_subtype == 2:  # TSPEC Element
                    pass

        return out

    def _parse_extension_tag_element(self, element_data):
        """
        elements are defined to have a common general format consisting of a 1 octet Element ID field, a 1 octet
        length field, an optional 1 octet Element ID Extension field, and a variable-length element-specific
        information field. Each element is identified by the contents of the Element ID and, when present, Element
        id Extension fields as defined in this standard. An Extended Element ID is a combination of an Element ID
        and an Element ID Extension for those elements that have a defined Element ID Extension. The Length field
        specifies the number of octets following the Length field.

        the presence of the Element ID Extension field is determined by the Element ID field.
        """
        eid_ext = element_data[0]

        body = list(memoryview(element_data))

        out = ""
        ext_tag_name = ""

        ext_tag_name = EXTENSION_IE_DICT.get(eid_ext, None)

        # based on Aruba AP515 802.11ax pcap.
        if eid_ext == 35:  # HE Capabilities
            if self is not None:
                self.phy_type.name = "HE"
                if "ax" not in self.modes:
                    self.modes.append("ax")

        if eid_ext == 36:  # HE Operation
            bit0 = get_bit(body[4], 0)
            bit1 = get_bit(body[4], 1)
            bit2 = get_bit(body[4], 2)
            bit3 = get_bit(body[4], 3)
            bit4 = get_bit(body[4], 4)
            bit5 = get_bit(body[4], 5)
            bits = bools_to_binary_string([bit5, bit4, bit3, bit2, bit1, bit0])
            bss_color = binary_string_to_int(bits)
            if bss_color != 0:
                out = f"BSS Color: {bss_color}"
            if self is not None:
                if not out:
                    self.bsscolor.value = bss_color
                if "ax" not in self.modes:
                    self.modes.append("ax")

        return ext_tag_name, out

    def _parse_vht_capabilities_element(self, edata):
        """
        first 4 octets are VHT Capabilities Info.
        then 8 next octets are the supported VHT-MCS and NSS set.
        """
        # parse VHT Capabilities Info

        if self is not None:
            if "ac" not in self.modes:
                self.modes.append("ac")

        out = "Info: 0x{:02x}".format(edata[3])
        out += "{:02x}".format(edata[2])
        out += "{:02x}".format(edata[1])
        out += "{:02x}\n".format(edata[0])
        out += " {0:08b}".format(edata[3])
        out += "{0:08b}".format(edata[2])
        out += "{0:08b}".format(edata[1])
        out += "{0:08b}\n".format(edata[0])
        out += "MCS Set\n"
        out += " Rx MCS Map: 0x{:02x}".format(edata[11])
        out += "{:02x}".format(edata[10])
        out += "{:02x}".format(edata[9])
        out += "{:02x}\n".format(edata[8])
        out += " {0:0b}".format(edata[11])
        out += "{0:0b}".format(edata[10])
        out += "{0:0b}".format(edata[9])
        out += "{0:0b}\n".format(edata[8])
        out += " Tx MCS Map: 0x{:02x}".format(edata[7])
        out += "{:02x}".format(edata[6])
        out += "{:02x}".format(edata[5])
        out += "{:02x}\n".format(edata[4])
        out += " {0:0b}".format(edata[7])
        out += "{0:0b}".format(edata[6])
        out += "{0:0b}".format(edata[5])
        out += "{0:0b}\n".format(edata[4])
        return out

    def _parse_vht_operation_element(self, edata):
        """
        bits 2 and 3 of the VHT Operation Info are for the Supported Channel Width Set.
        """

        if self is not None:
            if "ac" not in self.modes:
                self.modes.append("ac")

        body = list(memoryview(edata))
        channel_width = bool(body[0])
        out = "VHT Channel Width: {}, ".format(channel_width)
        channel_center_frequency_segment_zero = body[1]
        out += "Center Freq. 0: {}, ".format(channel_center_frequency_segment_zero)
        channel_center_frequency_segment_one = body[2]
        out += "Center Freq. 1: {}".format(channel_center_frequency_segment_one)
        if body[0] == 0:
            vht_channel_width = False
        if body[0] == 1:
            vht_channel_width = True
            if self is not None:
                self.channel_width.value = "80"
                for k, v in _80MHZ_CHANNEL_LIST.items():
                    if self.channel_number.value in v:
                        self.channel_list = " ".join(_80MHZ_CHANNEL_LIST[k])
                # self.channel.number = self.channel.number.split(",")[0] + ",+2"
                self.vht_channel_width = True
                self.channel_marking = ""
            if vht_channel_width:
                if channel_center_frequency_segment_one > 0:
                    if self is not None:
                        self.channel_width.value = "160"
                        self.channel_marking = ""
                        for k, v in _160MHZ_CHANNEL_LIST.items():
                            if self.channel_number.value in v:
                                self.channel_list = " ".join(_160MHZ_CHANNEL_LIST[k])
                        # self.channel.number = self.channel.number.split(",")[0] + ",+3"
        # vht_channel_width = body[0]
        return out
        # return "VHT Channel Width: {}".format(vht_channel_width)

    def _parse_overlapping_bss_scan_parameters_element(edata):
        """
        the Overlapping BSS Scan Parameters element is used by an AP to indicate the values to be used by BSS
        members when performing OBSS scan operations.
        """
        obss_scan_passive_dwell = edata[0] + edata[1]
        obss_scan_active_dwell = edata[2] + edata[3]
        bss_channel_width_trigger_scan_interval = edata[4] + edata[5]
        obss_scan_passive_total_per_channel = edata[6] + edata[7]
        obss_scan_active_total_per_channel = edata[8] + edata[9]
        bss_width_channel_transition_delay_factor = edata[10] + edata[11]
        obss_scan_activity_threshold = edata[12] + edata[13]
        return "Scan Passive Dwell: {}\nScan Active Dwell: {}\nChannel Width Triggger Scan Interval: {}\nScan Passive Total Per Channel: {}\nScan Active Total Per Channel: {}\nWidth Channel Transition Delay Factor: {}\nScan Activity Threshold: {}".format(
            obss_scan_passive_dwell,
            obss_scan_active_dwell,
            bss_channel_width_trigger_scan_interval,
            obss_scan_passive_total_per_channel,
            obss_scan_active_total_per_channel,
            bss_width_channel_transition_delay_factor,
            obss_scan_activity_threshold,
        )

    def _parse_interworking_hotspot_two_point_zero(self, edata):
        """
        interworking information element (802.11u)
        todo
        """
        body = list(memoryview(edata))
        network_type = None
        network_type = bools_to_binary_string(
            [
                get_bit(body[0], 0),
                get_bit(body[0], 1),
                get_bit(body[0], 2),
                get_bit(body[0], 3),
            ]
        )
        internet = get_bit(body[0], 4)
        asra = get_bit(body[0], 5)
        esc = get_bit(body[0], 6)
        uesa = get_bit(body[0], 7)
        network_type = INTERWORKING_NETWORK_TYPE.get(network_type, None)
        if self is not None:
            self.amendments.append("u")
        return ""

    def _parse_mesh_configuration(self, edata):
        """
                the Mesh Configuration element shown in Figure 9-451 is used to advertise mesh services. It is contained in
        Beacon frames and Probe Response frames transmitted by mesh STAs and is also contained in Mesh Peering
        Open and mesh Peering Confirm frames.
        """
        if self is not None:
            self.amendments.append("s")
        return ""

    def _parse_ap_channel_report_element(edata, elength):
        """
        the AP Channel Report element contains a list of channels where a STA is likely to find an AP.
        :"""
        operating_class = edata[0]
        count = 1
        # channel_list = ""
        channel_list = []
        while count < elength:
            channel_list.append(edata[count])
            count += 1
        # out = list(map(int, channel_list))

        # count = 1
        # out = ""
        # for channel in channel_list:
        #     if channel is not channel_list[0]:
        #         out += "{}, ".format(channel)
        #     else:
        #         out += "[{}, ".format(channel)
        #     if channel == channel_list[-1]:
        #         out += "]".format(channel)
        #         break
        #     if count % 15 == 0:
        #         out += "\n"
        #     count += 1
        return f"Operating Class {operating_class}, Channel List: \n{channel_list}"

    def _parse_ht_operation_element(self, edata):
        body = list(memoryview(edata))
        primary_channel = body[0]
        secondary_channel_offset1 = bools_to_binary_string(
            [get_bit(body[1], 1), get_bit(body[1], 0)]
        )
        secondary_channel_offset = binary_string_to_int(secondary_channel_offset1)
        sta_channel_width = get_bit(body[1], 2)
        # set to 1 (SCA) if the secondary channel is above the primary channel
        # print(f"{self.ssid} {primary_channel} {sta_channel_width} {secondary_channel_offset} {secondary_channel_offset1}")
        if secondary_channel_offset == 1:
            if self is not None:
                # self.channel.number = self.channel.number + ",+1"
                self.channel_marking = "+"
                self.channel_width.value = "40"
        # set to 3 (SCB) if the secondary channel is below the primary channel
        if secondary_channel_offset == 3:
            if self is not None:
                # self.channel.number = self.channel.number + ",-1"
                self.channel_marking = "-"
                self.channel_width.value = "40"
        # set to 0 for a single primary 20 MHz channel width
        if secondary_channel_offset == 0:
            if self is not None:
                self.channel_width.value = "20"
        # set to 1 allows use of any channel width in the
        # supported channel width set
        if sta_channel_width == 1:
            if self is not None:
                # print(f"{self.channel_number.value + self.channel_marking}")
                if self.channel_width.value == "20":
                    self.channel_list = self.channel_number.value
                else:
                    channels = _40MHZ_CHANNEL_LIST.get(
                        self.channel_number.value + self.channel_marking, ""
                    )
                    self.channel_list = " ".join(channels)
        # print(f"{self.bssid} {self.ssid} {self.channel_width.value}")
        return (
            f"Primary Channel: {primary_channel}, "
            f"HT Channel Width: {sta_channel_width}, "
            f"Secondary Channel Offset: {secondary_channel_offset}"
        )

    def _parse_ht_capabilities_element(self, edata):
        """
        9.4.2.56 HT Capabilities element

        an HT AP declares its channel width capability (20 MHz only or 20/40 MHz) in the Supported Channel Width
        set subfield of the HT Capabilities element.
        """

        if self is not None:
            if "n" not in self.modes:
                self.modes.append("n")

        body = list(memoryview(edata))

        supported_channel_width_set = get_bit(body[0], 1)

        ss = str(round((body[3] + body[4] + body[5] + body[6]) / 255))

        if self is not None:
            # set to 0 if only 20 MHz operation is supported
            # set to 1 if both 20 MHz and 40 MHz operation is support.
            if get_bit(body[0], 1):
                self.ht_channel_width = True
                # self.channelwidth = "40"

            if ss == "0":
                self.spatial_streams.value = 1
            else:
                self.spatial_streams.value = ss

            return (
                f"Supported Channel Width Set: {supported_channel_width_set}\n"
                f"Spatial Streams: {self.spatial_streams}"
            )
        else:
            return (
                f"Supported Channel Width Set: {supported_channel_width_set}\n"
                f"Spatial Streams: {ss}"
            )

    def _parse_rsn_element(self, edata):
        """
        the RSNE contains the information required to establish an RSNA

        rsnE size is limited by size of an element which is 255 octets.

        the RSNE contains up to and including the Version field. All fields after the Version field are optional.
        if any nonzero-length field is absent, then none of the subsequent fields is included.

        the Version field indicates the version number of the RSN protocol. Version 1 is defined in 802.11-2016.
        """
        if self is not None:
            self.amendments.append("i")
        body = list(memoryview(edata))
        version = body[0] + body[1]
        group_cipher_oui = convert_mac_address_to_string([body[i] for i in [2, 3, 4]])
        group_cipher_suite = body[5]
        pairwise_cipher_suite_count = body[6] + body[7]
        index = 8
        pairwise_list = []
        count = 0
        while count < pairwise_cipher_suite_count:
            # print("pairwise loop {} {}".format(count, self.bssid))
            pairwise_cipher_oui = convert_mac_address_to_string(
                [body[i] for i in [index, index + 1, index + 2]]
            )
            pairwise_cipher_suite = body[index + 3]
            # print(pairwise_cipher_suite)
            try:
                pairwise_list.append(f"{CIPHER_SUITE_DICT[pairwise_cipher_suite]}")
            except KeyError:
                pairwise_list.append(f"unknown({pairwise_cipher_suite})")
            index += 4
            count += 1
        akm_cipher_suite_count = body[index] + body[index + 1]
        index += 2
        akm_list = []
        count = 0
        # print("akm before index {}".format(index))
        # print("akm counter value {}".format(akm_cipher_suite_count))
        while count < akm_cipher_suite_count:
            akm_oui = convert_mac_address_to_string(
                [body[i] for i in [index, index + 1, index + 2]]
            )
            akm_suite = body[index + 3]
            try:
                akm_list.append(f"{AKM_SUITE_DICT[akm_suite]}")
            except KeyError:
                akm_list.append(f"unknown({akm_suite})")
            index += 4
            count += 1
        if self is not None:
            self.security.value = "{}/{}/{}".format(
                ",".join(akm_list),
                ",".join(pairwise_list),
                CIPHER_SUITE_DICT[group_cipher_suite],
            )
        out = "Version: {} Group: {} {}, Pairwise: {}, AKM: {}\n".format(
            str(version) + ",",
            group_cipher_oui,
            "/".join(akm_list),
            "/".join(pairwise_list),
            CIPHER_SUITE_DICT[group_cipher_suite],
        )
        PREAUTH = get_bit(body[index], 0)
        NO_PAIRWISE = get_bit(body[index + 1], 1)
        PTKSA1 = get_bit(body[index], 2)
        PTKSA2 = get_bit(body[index], 3)
        GTKSA1 = get_bit(body[index], 4)
        GTKSA2 = get_bit(body[index], 5)
        MFPR = get_bit(body[index], 6)
        MFPC = get_bit(body[index], 7)
        JOINT_MULTIBAND_RSNA = get_bit(body[index + 1], 0)
        PEERKEY_ENABLED = get_bit(body[index + 1], 1)
        # out += "{}{}{}{}{}{}{}{}{}{}\n".format(
        #    int(PEERKEY_ENABLED),
        #    int(JOINT_MULTIBAND_RSNA),
        #    int(MFPC),
        #    int(MFPR),
        #    int(GTKSA2),
        #    int(GTKSA1),
        #    int(PTKSA2),
        #    int(PTKSA1),
        #    int(NO_PAIRWISE),
        #    int(PREAUTH),
        # )
        RSN_CAP0 = "{}".format(
            int(
                "{}{}{}{}{}{}{}{}".format(
                    int(MFPC),
                    int(MFPR),
                    int(GTKSA2),
                    int(GTKSA1),
                    int(PTKSA2),
                    int(PTKSA1),
                    int(NO_PAIRWISE),
                    int(PREAUTH),
                ),
                2,
            )
        )
        RSN_CAP1 = "{}".format(
            int("{}{}".format(int(PEERKEY_ENABLED), int(JOINT_MULTIBAND_RSNA)), 2)
        )
        if MFPC:
            if self is not None:
                if "w" not in self.amendments:
                    self.amendments.append("w")
        if MFPR:
            if self is not None:
                if "w" not in self.amendments:
                    self.amendments.append("w")
        out += "RSN Capabilities 0x{:02x}{:02x}\n".format(
            int(RSN_CAP1), int(RSN_CAP0), body[index + 1], body[index]
        )
        return out

    def _parse_quiet_element(self, edata):
        """
        The Quiet element defines an interavl during which no transmission occurs in the current channel.
        This interval might be used to assist in making channel measurements without interference from
        other STAs in the BSS.
        """
        if self is not None:
            if "h" not in self.amendments:
                self.amendments.append("h")
        quiet_count = edata[0]
        quiet_period = edata[1]
        quiet_duration = edata[2] + edata[3]
        quiet_offset = edata[4] + edata[5]
        return (
            f"Count {quiet_count}, "
            f"Period {quiet_period}, "
            f"Duration {quiet_duration}, "
            f"Offset {quiet_offset}"
        )

    def _parse_erp_element(self, edata):
        """
        The ERP element contains information on the presence of Clause 15 or Clause 16 STAs in the BSS that are
        not capable of Clause 18 (ERP-OFDM) data rates. It also contains the requirement of the ERP element
        sender (AP, IBSS STA, or mesh STA) as to the use of protection mechanisms to optimize BSS performance
        and as to the use of long or short Barker preambles.

        B0 - NonERP_Present
        B1 - Use_Protection
        B2 - Barker_Preamble_Mode
        B3 - B7 reserved

        :param edata: raw element data
        :return: data for verbose output
        """
        body = list(memoryview(edata))
        nonERP_present = get_bit(body[0], 0)
        use_protection = get_bit(body[0], 1)
        barker_preamble_mode = get_bit(body[0], 2)
        if self is not None:
            pass

        return (
            f"Non-ERP Present: {int(nonERP_present)}, "
            f"Use Protection: {int(use_protection)}, "
            f"Barker Preamble Mode: {int(barker_preamble_mode)}"
        )

    def _parse_tpc_report_element(self, edata):
        if self is not None:
            if "h" not in self.amendments:
                self.amendments.append("h")
        transmit_power = edata[0]
        link_margin = edata[1]
        return f"Transmit Power: {transmit_power}, Link Margin: {link_margin}"

    def _parse_power_constraint_element(self, edata):
        if self is not None:
            if "h" not in self.amendments:
                self.amendments.append("h")
        return f"{int.from_bytes(edata, 'little')} dBm"

    def _parse_bss_load_element(self, edata):
        body = [edata[i : i + 1] for i in range(len(edata))]
        sta_count = int.from_bytes(body[0] + body[1], "little")
        channel_utilization = math.ceil((int.from_bytes(body[2], "big") / 255) * 100)
        available_admission_capacity = int.from_bytes(body[3] + body[4], "little")
        # TODO: calculate us/s per capacity e.g. 30625 (980000 us/s)
        if self is not None:
            self.stations.value = str(sta_count)
            self.utilization.value = "{}%".format(channel_utilization)
        return (
            f"Station count: {sta_count}, "
            f"Utilization: {channel_utilization}%, "
            f"Available Admission Capacity: {available_admission_capacity}"
        )

    def _parse_country_information_element(self, edata):
        cc_fmt = "3s"
        country = unpack_from(cc_fmt, edata)
        country = b" ".join(country)
        country = country.decode("utf-8").strip()
        if self is not None:
            self.country_code = country
            self.amendments.append("d")
        return f"{country}"

    def __parse_dsss_parameter_set_element(edata):
        return f"{int.from_bytes(edata, 'little')}"

    def __parse_tim_element(self, edata):
        body = list(memoryview(edata))
        dtim = body[1]
        if self is not None:
            self.dtim.value = dtim
        return f"DTIM Period: {dtim}"

    def __parse_rates(edata):
        """
        A BSS membership selector that has the MSB(bit 7) set to 1 in the Supported Rates and BSS Membership Selectors element is defined to be basic.
        This method supports either IE 1 or IE 50
        """
        supported_rates = ""
        for _byte in list(memoryview(edata)):
            # if MSB, rate is basic.
            if get_bit(_byte, 7):
                supported_rates += " {}*".format(
                    format_rate(rate_to_mbps(trim_most_significant_bit(_byte)))
                )
            else:
                supported_rates += " {}".format(format_rate(rate_to_mbps(_byte)))
        return supported_rates

    def __parse_ssid_element(edata):
        """
        The SSID element indicates the identity of an ESS or IBSS.
        The SSID field is between 0 and 32 octets.
        """
        return f"{edata.decode()}"
