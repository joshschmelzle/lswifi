#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

"""
lswifi.capabilities
~~~~~~~~~~~~~~~~~~~

schema definition for capabilities
"""

from ctypes import Structure, Union, c_ushort


class CapabilityInformationBits(Structure):
    """802.11-2016 9.4.1.4 Capability Information field

    The 16-bit Capability Information field is used in
      Beacon transmissions to advertise the network’s capabilities.
    Capability Information is also used in Probe Request
      and Probe Response frames. In this field, each bit is used as a flag
      to advertise a particular function of the network.
    Stations use the capability advertisement to determine
      whether they can support all the features in the BSS.
    Stations that do not implement all the features in the capability
      advertisement are not allowed to join.
    """

    _fields_ = [
        ("ESS", c_ushort, 1),  # bit 0
        ("IBSS", c_ushort, 1),  # bit 1
        ("CF_POLLABLE", c_ushort, 1),  # bit 2
        ("CF_POLL_REQUEST", c_ushort, 1),  # bit 3
        ("PRIVACY", c_ushort, 1),  # bit 4
        ("SHORT_PREAMBLE", c_ushort, 1),  # bit 5
        ("PBCC", c_ushort, 1),  # bit 6 - Packet Binary Convolutional Code
        ("CHANNEL_AGILITY", c_ushort, 1),  # bit 7
        ("SPECTRUM_MANAGEMENT", c_ushort, 1),  # bit 8
        ("QOS", c_ushort, 1),  # bit 9
        ("SHORT_SLOT_TIME", c_ushort, 1),  # bit 10
        ("APSD", c_ushort, 1),  # bit 11 - WMM Automatic Power Save Delievery
        ("RADIO_MEASUREMENT", c_ushort, 1),  # bit 12
        ("DSSS_OFDM", c_ushort, 1),  # bit 13
        ("DELAYED_BLOCK_ACK", c_ushort, 1),  # bit 14
        ("IMMEDIATE_BLOCK_ACK", c_ushort, 1),  # bit 15
    ]


class CapabilityInformation(Union):
    _fields_ = [("bits", CapabilityInformationBits), ("asbyte", c_ushort)]


class Capabilities:
    """Base class for Capabilities"""

    def __init__(self, capability: int):
        """:param capability: 16-bit Capability Information field"""
        self.value = capability
        self.ci = CapabilityInformation()
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
