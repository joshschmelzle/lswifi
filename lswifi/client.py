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
from subprocess import check_output
from threading import Timer
from types import SimpleNamespace
from typing import Union

from . import wlanapi as WLAN_API
from .wlanapi import (
    ONEX_NOTIFICATION_TYPE_ENUM,
    WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
    WLAN_NOTIFICATION_ACM_ENUM,
    WLAN_NOTIFICATION_MSM_ENUM,
    WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_NOTIFICATION_SOURCE_ALL,
    WLAN_NOTIFICATION_SOURCE_DICT,
    WLAN_NOTIFICATION_SOURCE_HNWK,
    WLAN_NOTIFICATION_SOURCE_IHV,
    WLAN_NOTIFICATION_SOURCE_MSM,
    WLAN_NOTIFICATION_SOURCE_NONE,
    WLAN_NOTIFICATION_SOURCE_ONEX,
    WLAN_NOTIFICATION_SOURCE_SECURITY,
    WLANConnectionAttributes,
)


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
    logging.getLogger(__name__)
    outstr = ""
    interface_info = {}

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
            return outstr

    isState = None
    connected = False
    if "current_connection" in interface_info.keys():
        if "isState" in interface_info["current_connection"][1]:
            isState = interface_info["current_connection"][1]["isState"]

    if isState == "connected":
        connected = True

    if not args.get_current_channel and not args.get_current_ap:
        if connected:
            outstr += f"Interface: {iface.description} is connected\n"
        else:
            outstr += f"Interface: {iface.description} is disconnected\n"

    if not args.supported:
        # print(interface_info.items())
        bssid = ""
        for key, result in interface_info.items():
            if key == "current_connection":
                if isinstance(result[0], WLANConnectionAttributes):
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
                    if args.event_watcher:
                        return bssid
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
                    outstr += f"    Security: {'Enabled' if SecurityEnabled else 'Disabled'}\n"
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
    else:
        return ""


class Client(object):
    scan_finished = False
    data = None
    guid = ""
    mac = ""
    log = logging.getLogger(__name__)
    get_bssid_args = SimpleNamespace(
        get_current_ap=True,
        raw=True,
        event_watcher=True,
        get_current_channel=False,
        supported=False,
    )

    def get_bss_list(self, interface) -> Union[list, None]:
        if interface:
            wireless_network_bss_list = WLAN_API.WLAN.get_wireless_network_bss_list(
                interface
            )
            if len(wireless_network_bss_list) == 0:
                return None

            return wireless_network_bss_list
        else:
            return None

    def on_event_notification(self, wlan_event) -> None:
        if wlan_event is not None:
            # attempt to get connected bssid
            bssid = get_interface_info(self.get_bssid_args, self.iface)

            # if we want to watch wlan events on the terminal
            if self.args.event_watcher:
                # if str(wlan_event).strip() in ["interface_removal", "interface_arrival"]:
                #    self.mac = self.lookup_mac_on_guid(self.iface)
                # if we want verbose info printed to the terminal
                if self.args.debug:
                    if str(wlan_event).strip() in [
                        "scan_list_refresh",
                        "scan_complete",
                    ]:
                        self.data = self.get_bss_list(self.iface)
                        if self.data is not None:
                            self.log.info(
                                f"({self.mac}), bssid: ({bssid}), event: ({wlan_event}), get_bss_list: ({len(self.data)} BSSIDs)"
                            )
                    else:
                        self.log.info(
                            f"({self.mac}), bssid: ({bssid}), event: ({wlan_event})"
                        )
                else:
                    self.log.info(
                        f"({self.mac}), bssid: ({bssid}), event: ({wlan_event})"
                    )

            # if we're not watching for events and we want to return scan results
            if not self.args.event_watcher:
                self.log.debug(f"({self.mac}), bssid: ({bssid}), event: ({wlan_event})")

                if str(wlan_event).strip() == "scan_complete":
                    self.scan_timer.cancel()

                # if the list is updated, grab the results
                if str(wlan_event).strip() == "scan_list_refresh":

                    self.log.debug(f"({self.mac}), start get_bss_list...")
                    self.data = self.get_bss_list(self.iface)
                    self.log.debug(f"({self.mac}), finish get_bss_list...")
                    self.scan_finished = True

                # if str(wlan_event).strip() == "network_available":
                #    pass
                #

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
            self.scan_timer.start()
            WLAN_API.WLAN.scan(self.iface.guid)
        except WLAN_API.WLANScanError as scan_error:
            self.log.critical(
                "Interface (%s) with GUID (%s): %s",
                self.iface.description,
                self.iface.guid_string[1:-1],
                scan_error,
            )

    def lookup_mac_on_guid(self, iface) -> str:
        guid = str(iface.guid)[1:-1]  # remove { } around guid
        result = guid  # store guid in result
        exe = 'getmac.exe /FO "CSV" /V'  # use getmac.exe to map interface guid to mac
        cmd = f"{exe}"
        try:
            output = check_output(cmd)
            mac = ""
            self.log.debug(
                "checking output from '%s' for client mac lookup on guid", exe
            )
            for line in output.decode().splitlines():
                if guid in line or iface.description in line:
                    conn = line.split(",")
                    mac = conn[2].replace('"', "")
                    result = mac.lower().replace("-", ":")
                    self.log.debug(f"guid {guid} maps to {result}")
                    break
        except FileNotFoundError:
            pass
        finally:
            return result

    def scan_timeout(self) -> None:
        """
        The application should then wait to receive the
          wlan_notification_acm_scan_complete notification or timeout after 4 seconds.
        Then the application can call the WlanGetNetworkBssList or WlanGetAvailableNetworkList
          function to retrieve a list of available wireless networks.
        """
        self.log.info(f"timeout interval ({self.timeout_interval} seconds) exceeded...")
        self.log.debug(f"({self.mac}), start get_bss_list...")
        self.data = self.get_bss_list(self.iface)
        self.log.debug(f"({self.mac}), finish get_bss_list...")
        self.scan_finished = True

    def __init__(self, args, iface, ssid=None):
        try:
            self.timeout_interval = 4.0
            self.scan_timer = Timer(self.timeout_interval, self.scan_timeout)
            self.args = args
            self.iface = iface
            self.mac = self.lookup_mac_on_guid(iface)
            # self.first_event = True
            self.client_handle = WLAN_API.WLAN.open_handle()
            callback = self.register_notification(
                self.on_event_notification, self.client_handle
            )
            callbacks.append(callback)
            self.log.debug(f"callback {callback} added")
            handles.append(self.client_handle)
            self.log.debug(f"handle {self.client_handle} added")
        except Exception:
            traceback.print_exc()
            WLAN_API.WLAN.close_handle(self.client_handle)
