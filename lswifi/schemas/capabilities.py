# -*- coding: utf-8 -*-

"""
lswifi.capabilities
~~~~~~~~~~~~~~~~~~~

schema definition for capabilities
"""

from lswifi import wlanapi as WLAN_API


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
