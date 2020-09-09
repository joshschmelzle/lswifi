# -*- coding: utf-8 -*-

"""
lswifi.client
~~~~~~~~~~~~~

client side code for requesting a scan, waiting for scan complete, and getting the results.
"""

import traceback
from datetime import datetime
from . import wlanapi as WLAN_API
import functools
from .wlanapi import (
    WLAN_NOTIFICATION_SOURCE_NONE,
    WLAN_NOTIFICATION_SOURCE_ONEX,
    WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_NOTIFICATION_SOURCE_MSM,
    WLAN_NOTIFICATION_SOURCE_SECURITY,
    WLAN_NOTIFICATION_SOURCE_IHV,
    WLAN_NOTIFICATION_SOURCE_HNWK,
    WLAN_NOTIFICATION_SOURCE_ALL,
    ONEX_NOTIFICATION_TYPE_ENUM,
    WLAN_NOTIFICATION_ACM_ENUM,
    WLAN_NOTIFICATION_MSM_ENUM,
    WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
    WLAN_NOTIFICATION_SOURCE_DICT,
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


import logging
import asyncio


class Client(object):
    scan_finished = False
    data = None
    guid = ""
    log = logging.getLogger(__name__)

    def get_bss_list(self, interface) -> list:
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
            now = datetime.now().strftime("%Y-%m-%dt%H:%M:%S.%f")
            event = {
                str(wlan_event.interfaceGuid): [
                    datetime.now().strftime("%Y-%m-%dt%H:%M:%S.%f"),
                    str(wlan_event),
                ]
            }
            # msg = json.dumps(event)

            if self.args.event_watcher:
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
                    # await asyncio.sleep(0.1)
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

    def watch(self):
        pass

    async def scan(self):
        try:
            now = datetime.now().strftime("%Y-%m-%dt%H:%M:%S.%f")
            self.log.debug(f"{self.iface.guid}: scan requested...")
            # print(f"{now} - {self.iface.guid}: scan requested...")
            WLAN_API.WLAN.scan(self.iface.guid)
        except WLAN_API.WLANScanError as scan_error:
            self.log.critical(scan_error)
            # print(scan_error)

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
