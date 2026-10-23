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
lswifi.backends.windows
~~~~~~~~~~~~~~~~~~~~~~~

thin adapter over the Native Wifi code in lswifi.wlanapi and lswifi.client.
those modules are imported lazily so this module is importable on any OS.
"""

import asyncio
import time
from ctypes import addressof, c_char
from types import SimpleNamespace

from lswifi.backends.base import BackendUnavailableError, BssRecord, InterfaceInfo
from lswifi.helpers import convert_mac_address_to_string


def _get_information_elements_buffer(bss_entry):
    """
    gets the buffer containing the information elements bytes

    the IE blob is not a separate buffer: it sits IeOffset bytes past the
    start of the WLAN_BSS_ENTRY struct.
    """
    bss_entry_pointer = addressof(bss_entry)
    ie_offset = bss_entry.IeOffset
    data_type = c_char * bss_entry.IeSize
    ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
    return ie_buffer


def bss_entry_to_record(bss_entry, connected_bssid=None, include_ies=True) -> BssRecord:
    """Map a wlanapi WLANBSSEntry to a BssRecord.

    Copies everything out of the entry, so the record stays valid after
    WlanFreeMemory releases the BSS list.

    include_ies=False is for a WLAN_BSS_ENTRY loaded from a .bss file,
    where the bytes at IeOffset are not part of the buffer.
    """
    from lswifi import wlanapi as WLAN_API

    bssid = convert_mac_address_to_string(bss_entry.dot11Bssid)
    ies = b""
    if include_ies:
        ies = bytes(_get_information_elements_buffer(bss_entry))
    return BssRecord(
        # c_char array fields read as bytes up to the first NUL
        ssid=bss_entry.dot11Ssid.SSID[: WLAN_API.DOT11_SSID_MAX_LENGTH],
        bssid=bssid,
        frequency_mhz=bss_entry.ChCenterFrequency // 1000,
        rssi_dbm=bss_entry.Rssi,
        link_quality=bss_entry.LinkQuality,
        beacon_interval_tu=bss_entry.BeaconPeriod,
        tsf=bss_entry.Timestamp,
        host_timestamp=bss_entry.HostTimestamp,
        capability=bss_entry.CapabilityInformation,
        ies=ies,
        phy_name=WLAN_API.DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType],
        bss_type=WLAN_API.DOT11_BSS_TYPE_DICT[bss_entry.dot11BssType],
        rate_set=list(
            bss_entry.WlanRateSet.RateSet[: bss_entry.WlanRateSet.RateSetLength]
        ),
        connected=bssid == connected_bssid,
        ie_source=None,
        phy_id=bss_entry.PhyId,
        in_reg_domain=bool(bss_entry.InRegDomain),
        raw=bss_entry.send(),
    )


def wireless_interface_to_info(iface) -> InterfaceInfo:
    return InterfaceInfo(
        connection_name=iface.connection_name,
        description=iface.description,
        guid_string=iface.guid_string,
        mac=iface.mac,
        state_string=iface.state_string,
        native=iface,
    )


class WindowsBackend:
    """Native Wifi (wlanapi.dll) backend"""

    name = "windows"
    supports_events = True

    def __init__(self) -> None:
        from lswifi import wlanapi as WLAN_API

        if not WLAN_API.WLAN_API_EXISTS:
            raise BackendUnavailableError(
                "wlanapi.dll could not be loaded; is the WLAN AutoConfig service installed?"
            )
        self.wlanapi = WLAN_API

    def list_interfaces(self) -> list[InterfaceInfo]:
        ifaces = self.wlanapi.WLAN.get_wireless_interfaces()
        return [wireless_interface_to_info(iface) for iface in ifaces.values()]

    def open_session(self, args, iface: InterfaceInfo):
        """Client opens a handle and registers for ACM/MSM notifications"""
        from lswifi.client import Client

        return Client(args, iface.native)

    def interface_info(self, args, iface: InterfaceInfo) -> str:
        """-ap, -channel, --get-interfaces via WlanQueryInterface"""
        from lswifi.client import get_interface_info

        return get_interface_info(args, iface.native)

    def bus_info(self, iface: InterfaceInfo) -> tuple:
        from lswifi.client import get_adapter_bus_info

        guid = iface.guid_string.replace("{", "").replace("}", "")
        return get_adapter_bus_info(guid)

    def scan(self, iface: InterfaceInfo) -> list[BssRecord]:
        """Trigger WlanScan and return the BSS list as records.

        Waits for scan_list_refresh or the client's scan timeout, like the
        CLI does. lswifi.app drives Client directly; this is the neutral API.
        """
        args = SimpleNamespace(bytes=None, event_watcher=False, syslog=None)
        client = self.open_session(args, iface)
        asyncio.run(client.scan())
        deadline = time.time() + client.timeout_interval + 1
        while not client.scan_finished and time.time() < deadline:
            time.sleep(0.1)
        return self.wlanapi.WLAN.get_wireless_network_bss_records(iface.native)
