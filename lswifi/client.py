# -*- coding: utf-8 -*-

"""
lswifi.client
~~~~~~~~~~~~~

client side code for requesting a scan, waiting for scan complete, and getting the results.
"""

import functools
import logging
import pprint
import traceback
from types import SimpleNamespace
from typing import Union

from . import wlanapi as WLAN_API
from .wlanapi import (ONEX_NOTIFICATION_TYPE_ENUM,
                      WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
                      WLAN_NOTIFICATION_ACM_ENUM, WLAN_NOTIFICATION_MSM_ENUM,
                      WLAN_NOTIFICATION_SOURCE_ACM,
                      WLAN_NOTIFICATION_SOURCE_ALL,
                      WLAN_NOTIFICATION_SOURCE_DICT,
                      WLAN_NOTIFICATION_SOURCE_HNWK,
                      WLAN_NOTIFICATION_SOURCE_IHV,
                      WLAN_NOTIFICATION_SOURCE_MSM,
                      WLAN_NOTIFICATION_SOURCE_NONE,
                      WLAN_NOTIFICATION_SOURCE_ONEX,
                      WLAN_NOTIFICATION_SOURCE_SECURITY)


class Event(object):
    ns_type_to_codes_dict = {
        WLAN_NOTIFICATION_SOURCE_NONE: None,
        WLAN_NOTIFICATION_SOURCE_ONEX: ONEX_NOTIFICATION_TYPE_ENUM,
        WLAN_NOTIFICATION_SOURCE_ACM: WLAN_NOTIFICATION_ACM_ENUM,
        WLAN_NOTIFICATION_SOURCE_MSM: WLAN_NOTIFICATION_MSM_ENUM,
        WLAN_NOTIFICATION_SOURCE_SECURITY: None,
        WLAN_NOTIFICATION_SOURCE_IHV: None,
        WLAN_NOTIFICATION_SOURCE_HNWK: WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
        WLAN_NOTIFICATION_SOURCE_ALL: ONEX_NOTIFICATION_TYPE_ENUM,
    }

    def __init__(
        self, original, notification_source, notification_code, interface_guid
    ):
        self.original = original
        self.notificationSource = notification_source
        self.notificationCode = notification_code
        self.interfaceGuid = interface_guid

    @staticmethod
    def from_notification_data(notification_data):
        actual = notification_data.contents
        if actual.NotificationSource not in WLAN_NOTIFICATION_SOURCE_DICT:
            return None

        codes = Event.ns_type_to_codes_dict.get(
            actual.NotificationSource, WLAN_NOTIFICATION_SOURCE_NONE
        )
        if codes is not None:
            try:
                code = codes(actual.NotificationCode)

                event = Event(
                    actual,
                    WLAN_NOTIFICATION_SOURCE_DICT.get(
                        actual.NotificationSource, WLAN_NOTIFICATION_SOURCE_NONE
                    ),
                    code.name,
                    actual.InterfaceGuid,
                )
                return event
            except:
                return None

    def __str__(self):
        return self.notificationCode


callbacks = []
handles = []


class NotificationObject(object):
    def __init__(self, handle, callback):
        self.handle = handle
        self.callback = callback


def parse_result(result, data_type, **kwargs):
    data = kwargs.get("data", None)
    try:
        if data:
            return result[data_type][data]
        else:
            return result[data_type]
    except KeyError:
        if data:
            return f"unknown {data}"
        else:
            return f"unknown {data_type}"


def get_interface_info(args, iface) -> str:
    outstr = ""
    interface_info = {}
    connected = True

    if "disconnected" in iface.state_string:
        connected = False

    if not args.get_current_channel and not args.get_current_ap:
        if connected:
            outstr += f"Interface: {iface.description} is connected\n"
        else:
            outstr += f"Interface: {iface.description} is disconnected\n"

    # query interface for supported info
    params = ["current_connection", "channel_number", "statistics", "rssi"]
    for p in params:
        result = WLAN_API.WLAN.query_interface(iface, p)
        interface_info[p] = result

        if args.supported:
            if isinstance(result, tuple):
                outstr += f"    {p}: {pprint.pformat(result, indent=4)}\n"
            else:
                outstr += f"    {p}: {result}\n"

    if connected and not args.supported:
        # print(interface_info.items())
        bssid = ""
        for key, result in interface_info.items():
            if key == "current_connection":
                connected_ssid = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11Ssid",
                )
                bssid = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11Bssid",
                )
                dot11PhyType = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11PhyType",
                )
                wlanSignalQuality = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="wlanSignalQuality",
                )
                ulRxRate = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="ulRxRate",
                )
                ulTxRate = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="ulTxRate",
                )
                dot11BssType = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11BssType",
                )
                state = parse_result(result=result[1], data_type="isState")
                wlanConnectionMode = parse_result(
                    result=result[1], data_type="wlanConnectionMode"
                )
                strProfileName = parse_result(
                    result=result[1], data_type="strProfileName"
                )
                SecurityEnabled = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="bSecurityEnabled",
                )
                oneXEnabled = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="bOneXEnabled",
                )
                dot11AuthAlgorithm = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="dot11AuthAlgorithm",
                )
                dot11CipherAlgorithm = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="dot11CipherAlgorithm",
                )

                outstr += f"    Description: {iface.description}\n"
                outstr += (
                    f"    GUID: {iface.guid_string.strip('{').strip('}').lower()}\n"
                )
                outstr += f"    State: {state}\n"
                if "wlan_connection_mode_" in wlanConnectionMode:
                    wlanConnectionMode = wlanConnectionMode[21:]
                outstr += (
                    f"    Connection Mode: {wlanConnectionMode}\n"
                    f"    Profile Name: {strProfileName}\n"
                )
                outstr += f"    SSID: {bytes.decode(connected_ssid)}\n"
                outstr += f"    BSSID: {bssid}\n"
                outstr += f"    BSS Type: {dot11BssType}\n"
                outstr += f"    PHY: {dot11PhyType}\n"
                # out += "PH    Y Index: {}\n".format(uDot11PhyIndex)
                outstr += f"    Signal Quality: {wlanSignalQuality}%\n"
                outstr += f"    Rx Rate: {ulRxRate/1000} Mbps\n"
                outstr += f"    Tx Rate: {ulTxRate/1000} Mbps\n"
                outstr += (
                    f"    Security: {'Enabled' if SecurityEnabled else 'Disabled'}\n"
                )
                outstr += f"    .1X: {'Enabled' if oneXEnabled else 'Disabled'}\n"
                outstr += f"    Authentication: {dot11AuthAlgorithm}\n"
                outstr += f"    Cipher: {dot11CipherAlgorithm}\n"

            if "ERROR_NOT_SUPPORTED" in result:
                pass

            if "failed" not in result:
                if key == "channel_number":
                    channel = result[0].value

                    outstr += "    Channel: {}\n".format(channel)

                    if args.get_current_ap and args.get_current_channel:
                        if args.raw:
                            return f"{bssid}, {channel}"
                        else:
                            return f"Interface: {iface.description}, BSSID: {bssid}, CHANNEL: {channel}"

                    if args.get_current_ap:
                        if args.raw:
                            return bssid
                        else:
                            return f"Interface: {iface.description}, BSSID: {bssid}"

                    if args.get_current_channel:
                        if args.raw:
                            return channel
                        else:
                            return f"Interface: {iface.description}, Channel: {channel}"

    return outstr


class Client(object):
    scan_finished = False
    data = None
    guid = ""
    log = logging.getLogger(__name__)
    get_bssid_args = SimpleNamespace(
        get_current_ap=True, raw=True, get_current_channel=False, supported=False
    )

    def get_bss_list(self, interface) -> Union[list, None]:
        if interface:
            wireless_network_bss_list = WLAN_API.WLAN.get_wireless_network_bss_list(
                interface
            )
            self.scan_finished = True
            if len(wireless_network_bss_list) == 0:
                return None

            return wireless_network_bss_list
        else:
            return None

    def on_event_notification(self, wlan_event):
        if wlan_event is not None:
            if self.args.event_watcher:
                if str(wlan_event).strip() == "associated":
                    bssid = get_interface_info(self.get_bssid_args, self.iface)
                    self.log.info(f"{self.iface.guid}: {wlan_event} to {bssid}")
                else:
                    self.log.info(f"{self.iface.guid}: {wlan_event}")
            else:
                self.log.debug(f"{self.iface.guid}: <wlanapi.h> {wlan_event}...")

            if self.args.debug:
                if str(wlan_event).strip() == "scan_complete":
                    self.data = self.get_bss_list(self.iface)
                    if self.data is not None:
                        self.log.debug(
                            f"{self.iface.guid}: {len(self.data)} scan results..."
                        )
                    else:
                        self.log.debug(f"{self.iface.guid}: no scan results...")

            if not self.args.event_watcher:
                if str(wlan_event).strip() == "scan_complete":
                    pass
                if str(wlan_event).strip() == "scan_list_refresh":
                    self.log.debug(f"{self.iface.guid}: start get_bss_list...")
                    self.data = self.get_bss_list(self.iface)
                    self.log.debug(f"{self.iface.guid}: finish get_bss_list...")
                if str(wlan_event).strip() == "network_available":
                    pass

    def register_notification(self, callback, handle):
        c_back = WLAN_API.WLAN.wlan_register_notification(
            handle, functools.partial(self.on_wlan_notification, callback)
        )
        return NotificationObject(handle, c_back)

    @staticmethod
    def on_wlan_notification(callback, notification_data, p):
        event = Event.from_notification_data(notification_data)
        if event is not None:
            callback(event)

    def my_handle(self):
        return self.client_handle

    async def scan(self):
        try:
            self.log.debug(f"{self.iface.guid}: scan requested...")
            WLAN_API.WLAN.scan(self.iface.guid)
        except WLAN_API.WLANScanError as scan_error:
            self.log.critical(scan_error)

    def __init__(self, args, iface, ssid=None):
        try:
            self.args = args
            self.iface = iface
            self.client_handle = WLAN_API.WLAN.open_handle()
            callback = self.register_notification(
                self.on_event_notification, self.client_handle
            )
            callbacks.append(callback)
            self.log.debug(f"callback {callback} added")
            handles.append(self.client_handle)
            self.log.debug(f"handle {self.client_handle} added")
        except Exception as ex:
            traceback.print_exc()
            WLAN_API.WLAN.close_handle(self.client_handle)
