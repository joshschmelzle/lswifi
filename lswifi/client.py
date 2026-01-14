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
lswifi.client
~~~~~~~~~~~~~

client side code for requesting a scan, waiting for scan complete, and getting the results.
"""

import ctypes
import datetime
import functools
import json
import logging
import os
import pprint
import struct
import subprocess
import sys
import time
import traceback
import winreg
from ctypes import wintypes
from threading import Lock, Timer
from types import SimpleNamespace
from typing import Optional, Union

from lswifi import wlanapi as WLAN_API
from lswifi.helpers import (
    is_five_band,
    is_six_band,
    is_two_four_band,
)
from lswifi.slog import message as syslog

# PCI Express Link Speed Encoding (PciExpressCurrentLinkSpeedEncoded)
# https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterhardwareinfosettingdata
# Microsoft documents: 1=2.5Gbps (Gen1), 2=5Gbps (Gen2)
# Gen3-Gen5 values follow the same pattern per PCI-SIG specifications
PCIE_SPEEDS = {
    1: "2.5 GT/s",
    2: "5.0 GT/s",
    3: "8.0 GT/s",
    4: "16.0 GT/s",
    5: "32.0 GT/s",
}

# USB Device Speed Enumeration
# Values from USB_DEVICE_SPEED (usbspec.h) in Windows Driver Kit
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbspec/ne-usbspec-_usb_device_speed
USB_SPEEDS = {
    0: "Low Speed (USB 1.1)",
    1: "Full Speed (USB 1.1)",
    2: "High Speed (USB 2.0)",
    3: "SuperSpeed (USB 3.0)",
    4: "SuperSpeed+ (USB 3.1+)",
}

# Windows API constants for USB speed detection via IOCTL
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX_V2 = 0x22045C
GUID_DEVINTERFACE_USB_HUB = "{f18a0e88-c30c-11d0-8815-00a0c906bed8}"

_kernel32 = ctypes.windll.kernel32
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def get_adapter_bus_info(adapter_guid: str) -> tuple:
    """Get bus type and speed info for a network adapter.

    Args:
        adapter_guid: The adapter GUID (without braces)

    Returns:
        Tuple of (bus_type, bus_info) or (None, None) if not found
    """

    ps_cmd = f"""Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter |
        Where-Object {{ $_.InterfaceGuid -eq '{{{adapter_guid}}}' }} |
        Get-CimAssociatedInstance -ResultClassName MSFT_NetAdapterHardwareInfoSettingData |
        Select-Object BusType, PciExpressCurrentLinkSpeedEncoded, PciExpressCurrentLinkWidth, UsbCurrentSpeedEncoded |
        ConvertTo-Json"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if data:
                speed_encoded = data.get("PciExpressCurrentLinkSpeedEncoded")
                width = data.get("PciExpressCurrentLinkWidth")
                if speed_encoded is not None and width is not None:
                    speed = PCIE_SPEEDS.get(speed_encoded, f"Gen{speed_encoded}")
                    return "PCIe", f"{speed} x{width}"

                usb_speed = data.get("UsbCurrentSpeedEncoded")
                if usb_speed is not None:
                    speed = USB_SPEEDS.get(usb_speed, f"Unknown ({usb_speed})")
                    return "USB", speed

                bus_type = data.get("BusType")
                if bus_type == 15:
                    return "USB", None
    except Exception:
        pass

    ps_cmd = f"""Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter |
        Where-Object {{ $_.InterfaceGuid -eq '{{{adapter_guid}}}' }} |
        Select-Object PnpDeviceId |
        ConvertTo-Json"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if data:
                pnp_id = data.get("PnpDeviceId", "")
                if pnp_id and pnp_id.upper().startswith("USB\\"):
                    usb_speed = _get_usb_speed_from_pnp(pnp_id)
                    if usb_speed is not None:
                        speed = USB_SPEEDS.get(usb_speed, f"Unknown ({usb_speed})")
                        return "USB", speed
                    return "USB", None
                if pnp_id and pnp_id.upper().startswith("PCI\\"):
                    return "PCI", None
    except Exception:
        pass

    return None, None


def _is_usb_device_present(pnp_device_id: str) -> bool:
    """Check if USB device is currently present/connected.

    Args:
        pnp_device_id: The PnP device instance ID (e.g., USB\\VID_0E8D&PID_7961\\000000000)

    Returns:
        True if device is present, False otherwise
    """
    log = logging.getLogger(__name__)
    try:
        ps_cmd = f"""(Get-PnpDeviceProperty -InstanceId '{pnp_device_id}' -KeyName 'DEVPKEY_Device_IsPresent' -ErrorAction SilentlyContinue).Data"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip().lower() == "true"
    except Exception as e:
        log.debug("Failed to check device presence for %s: %s", pnp_device_id, e)
        return False


def _get_usb_parent_device(pnp_device_id: str) -> Optional[str]:
    """Get the immediate parent device (hub) for a USB device.

    Args:
        pnp_device_id: The PnP device instance ID

    Returns:
        Parent device instance ID or None if not found
    """
    log = logging.getLogger(__name__)
    try:
        ps_cmd = f"""(Get-PnpDeviceProperty -InstanceId '{pnp_device_id}' -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            parent = result.stdout.strip()
            log.debug("USB parent device for %s: %s", pnp_device_id, parent)
            return parent
    except Exception as e:
        log.debug("Failed to get parent device for %s: %s", pnp_device_id, e)
    return None


def _query_usb_speed_ioctl(hub_path: str, port_index: int) -> Optional[int]:
    """Query USB speed via IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX_V2.

    Args:
        hub_path: The device interface path to the USB hub
        port_index: The port number on the hub

    Returns:
        USB speed value (2=USB2.0, 3=USB3.0, 4=USB3.1+) or None on failure
    """
    log = logging.getLogger(__name__)

    handle = _kernel32.CreateFileW(
        hub_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )

    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.GetLastError()
        log.debug("CreateFileW failed for hub %s: error code %d", hub_path, error)
        return None

    log.debug("CreateFileW succeeded for hub %s, handle: %s", hub_path, handle)

    try:
        input_buffer = struct.pack("<IIII", port_index, 16, 0x04, 0)
        output_buffer = ctypes.create_string_buffer(16)
        bytes_returned = wintypes.DWORD()

        success = _kernel32.DeviceIoControl(
            handle,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX_V2,
            input_buffer,
            len(input_buffer),
            output_buffer,
            len(output_buffer),
            ctypes.byref(bytes_returned),
            None,
        )

        if not success:
            error = ctypes.GetLastError()
            log.debug("DeviceIoControl failed: error code %d", error)
            return None

        conn_index, length, protocols, flags = struct.unpack("<IIII", output_buffer.raw)

        log.debug(
            "IOCTL result: conn_index=%d, length=%d, protocols=0x%04x, flags=0x%04x",
            conn_index,
            length,
            protocols,
            flags,
        )
        log.debug("  protocols.Usb110: %s", bool(protocols & 0x01))
        log.debug("  protocols.Usb200: %s", bool(protocols & 0x02))
        log.debug("  protocols.Usb300: %s", bool(protocols & 0x04))
        log.debug(
            "  flags.DeviceIsOperatingAtSuperSpeedOrHigher: %s", bool(flags & 0x01)
        )
        log.debug("  flags.DeviceIsSuperSpeedCapableOrHigher: %s", bool(flags & 0x02))
        log.debug(
            "  flags.DeviceIsOperatingAtSuperSpeedPlusOrHigher: %s", bool(flags & 0x04)
        )
        log.debug(
            "  flags.DeviceIsSuperSpeedPlusCapableOrHigher: %s", bool(flags & 0x08)
        )

        # Interpret flags to determine operating speed
        if flags & 0x04:  # DeviceIsOperatingAtSuperSpeedPlusOrHigher
            return 4
        elif flags & 0x01:  # DeviceIsOperatingAtSuperSpeedOrHigher
            return 3
        else:
            return 2  # High Speed (USB 2.0)

    finally:
        _kernel32.CloseHandle(handle)


def _get_usb_speed_from_pnp(pnp_device_id: str) -> Optional[int]:
    """Get USB connection speed for a device using Windows IOCTL.

    Uses the Windows USB driver stack to query the actual operating speed
    of a USB device by communicating with its parent hub.

    Args:
        pnp_device_id: The PnP device instance ID (e.g., USB\\VID_0E8D&PID_7961\\000000000)

    Returns:
        USB speed value (0-4) or None if unable to determine:
        - 0: Low Speed (USB 1.1)
        - 1: Full Speed (USB 1.1)
        - 2: High Speed (USB 2.0)
        - 3: SuperSpeed (USB 3.0)
        - 4: SuperSpeed+ (USB 3.1+)
    """
    log = logging.getLogger(__name__)

    # Check if device is present first
    if not _is_usb_device_present(pnp_device_id):
        log.debug("USB device %s is not present/connected", pnp_device_id)
        return None

    try:
        # Get location info from registry to determine port number
        reg_path = f"SYSTEM\\CurrentControlSet\\Enum\\{pnp_device_id}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            location_info = winreg.QueryValueEx(key, "LocationInformation")[0]

        log.debug("USB device %s LocationInformation: %s", pnp_device_id, location_info)

        # Parse port number from "Port_#0002.Hub_#0003"
        port_match = location_info.split(".")[0]  # "Port_#0002"
        port_index = int(port_match.replace("Port_#", ""))

        log.debug("Parsed port_index: %d", port_index)

        # Get immediate parent hub
        parent_id = _get_usb_parent_device(pnp_device_id)
        if not parent_id:
            log.debug("Could not find parent hub for %s", pnp_device_id)
            return None

        # Build hub device interface path
        hub_path = (
            f"\\\\?\\{parent_id.replace(chr(92), '#')}#{GUID_DEVINTERFACE_USB_HUB}"
        )

        log.debug("Hub path: %s", hub_path)

        # Query speed via IOCTL
        return _query_usb_speed_ioctl(hub_path, port_index)

    except Exception as e:
        log.debug("Exception getting USB speed for %s: %s", pnp_device_id, e)
        return None


class TimerEx:
    """
    A reusable thread safe timer implementation
    """

    def __init__(self, interval_sec, function, *args, **kwargs):
        """
        Create a timer object which can be restarted

        :param interval_sec: The timer interval in seconds
        :param function: The user function timer should call once elapsed
        :param args: The user function arguments array (optional)
        :param kwargs: The user function named arguments (optional)
        """
        self._interval_sec = interval_sec
        self._function = function
        self._args = args
        self._kwargs = kwargs
        # Locking is needed since the '_timer' object might be replaced in a different thread
        self._timer_lock = Lock()
        self._timer = None

    def start(self, restart_if_alive=True):
        """
        Starts the timer and returns this object [e.g. my_timer = TimerEx(10, my_func).start()]

        :param restart_if_alive: 'True' to start a new timer if current one is still alive
        :return: This timer object (i.e. self)
        """
        with self._timer_lock:
            # Current timer still running
            if self._timer is not None:
                if not restart_if_alive:
                    # Keep the current timer
                    return self
                # Cancel the current timer
                self._timer.cancel()
            # Create new timer
            self._timer = Timer(self._interval_sec, self.__internal_call)
            self._timer.start()
        # Return this object to allow single line timer start
        return self

    def cancel(self):
        """
        Cancels the current timer if alive
        """
        with self._timer_lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def is_alive(self):
        """
        :return: True if current timer is alive (i.e not elapsed yet)
        """
        with self._timer_lock:
            if self._timer is not None:
                return self._timer.is_alive()
        return False

    def __internal_call(self):
        # Release timer object
        with self._timer_lock:
            self._timer = None
        # Call the user defined function
        self._function(*self._args, **self._kwargs)


class Event:
    """Native Wifi event class"""

    ns_type_to_codes_dict = {
        WLAN_API.WLAN_NOTIFICATION_SOURCE_NONE: None,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_ONEX: WLAN_API.ONEX_NOTIFICATION_TYPE_ENUM,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_ACM: WLAN_API.WLAN_NOTIFICATION_ACM_ENUM,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_MSM: WLAN_API.WLAN_NOTIFICATION_MSM_ENUM,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_SECURITY: None,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_IHV: None,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_HNWK: WLAN_API.WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
        WLAN_API.WLAN_NOTIFICATION_SOURCE_ALL: WLAN_API.ONEX_NOTIFICATION_TYPE_ENUM,
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
        if actual.NotificationSource not in WLAN_API.WLAN_NOTIFICATION_SOURCE_DICT:
            return None

        codes = Event.ns_type_to_codes_dict.get(
            actual.NotificationSource, WLAN_API.WLAN_NOTIFICATION_SOURCE_NONE
        )
        if codes is not None:
            try:
                code = codes(actual.NotificationCode)

                event = Event(
                    actual,
                    WLAN_API.WLAN_NOTIFICATION_SOURCE_DICT.get(
                        actual.NotificationSource,
                        WLAN_API.WLAN_NOTIFICATION_SOURCE_NONE,
                    ),
                    code.name,
                    actual.InterfaceGuid,
                )
                return event
            except Exception:
                return None

    def __str__(self):
        return self.notificationCode


callbacks = []
handles = []


class NotificationObject:
    def __init__(self, handle, callback):
        self.handle = handle
        self.callback = callback


def parse_result(result, data_type, **kwargs):
    data = kwargs.get("data")
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

    params = ["current_connection", "channel_number", "statistics", "rssi"]
    for param in params:
        result = WLAN_API.WLAN.query_interface(iface, param)
        interface_info[param] = result

        if args.supported:
            if isinstance(result, tuple):
                outstr += f"    {param}: {pprint.pformat(result, indent=4)}\n"
            else:
                outstr += f"    {param}: {result}\n"
            return outstr

    isState = None
    connected = False
    if (
        "current_connection" in interface_info
        and "isState" in interface_info["current_connection"][1]
    ):
        isState = interface_info["current_connection"][1]["isState"]

    if isState == "connected":
        connected = True

    if not args.get_current_channel and not args.get_current_ap:
        if connected:
            outstr += f"Interface: {iface.connection_name} is connected\n"
        else:
            outstr += f"Interface: {iface.connection_name} is disconnected\n"

    if not args.supported:
        # print(interface_info.items())
        bssid = ""
        for key, result in interface_info.items():
            if key == "current_connection" and isinstance(
                result[0], WLAN_API.WLANConnectionAttributes
            ):
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

                rssi = None
                channel = None
                band = None
                try:
                    bss_list = WLAN_API.WLAN.get_wireless_network_bss_list(
                        iface, is_bytes_arg=False
                    )
                    for bss in bss_list:
                        if str(bss.bssid) == bssid:
                            rssi = bss.rssi
                            channel = bss.channel_number.value
                            freq = bss.channel_frequency.value
                            if is_two_four_band(freq):
                                band = "2.4 GHz"
                            elif is_five_band(freq):
                                band = "5 GHz"
                            elif is_six_band(freq):
                                band = "6 GHz"
                            break
                except Exception:
                    pass

                outstr += f"    Description: {iface.description}\n"
                outstr += (
                    f"    GUID: {iface.guid_string.strip('{').strip('}').lower()}\n"
                )
                outstr += f"    MAC: {iface.mac}\n"
                guid_no_braces = iface.guid_string.strip("{}").lower()
                bus_type, bus_info = get_adapter_bus_info(guid_no_braces)
                if bus_type:
                    if bus_info:
                        outstr += f"    {bus_type}: {bus_info}\n"
                    else:
                        outstr += f"    Bus: {bus_type}\n"
                outstr += f"    State: {state}\n"
                if "wlan_connection_mode_" in wlanConnectionMode:
                    wlanConnectionMode = wlanConnectionMode[21:]
                outstr += (
                    f"    Connection Mode: {wlanConnectionMode}\n"
                    f"    Profile Name: {strProfileName}\n"
                )
                outstr += f"    SSID: {bytes.decode(connected_ssid)}\n"
                outstr += f"    BSSID: {bssid}\n"
                if channel is not None:
                    outstr += f"    Channel: {channel}\n"
                if band is not None:
                    outstr += f"    Band: {band}\n"
                outstr += f"    BSS Type: {dot11BssType}\n"
                outstr += f"    PHY: {dot11PhyType}\n"
                outstr += f"    Signal Quality: {wlanSignalQuality}%\n"
                if rssi is not None:
                    outstr += f"    RSSI: {rssi} dBm\n"
                outstr += f"    Receive (Rx) Rate: {ulRxRate / 1000} Mbps\n"
                outstr += f"    Transmit (Tx) Rate: {ulTxRate / 1000} Mbps\n"
                outstr += (
                    f"    Security: {'Enabled' if SecurityEnabled else 'Disabled'}\n"
                )
                outstr += f"    .1X: {'Enabled' if oneXEnabled else 'Disabled'}\n"
                outstr += f"    Authentication: {dot11AuthAlgorithm or 'None'}\n"
                outstr += f"    Cipher: {dot11CipherAlgorithm or 'None'}\n"

            if "ERROR_NOT_SUPPORTED" in result:
                pass

            if "failed" not in result and key == "channel_number":
                channel_from_query = result[0].value

                if args.get_current_ap and args.get_current_channel:
                    if args.raw:
                        return f"{bssid}, {channel_from_query}"
                    else:
                        return f"INTERFACE: {iface.connection_name}, MAC: {iface.mac}, BSSID: {bssid}, CHANNEL: {channel_from_query}"

                if args.get_current_ap:
                    if args.raw:
                        return bssid
                    else:
                        return f"INTERFACE: {iface.connection_name}, MAC: {iface.mac}, BSSID: {bssid}"

                if args.get_current_channel:
                    if args.raw:
                        return channel_from_query
                    else:
                        return f"INTERFACE: {iface.connection_name}, MAC: {iface.mac}, CHANNEL: {channel_from_query}"

        return outstr
    else:
        return ""


class Client:
    def __init__(self, args, iface, ssid=None):
        try:
            self.log = logging.getLogger(__name__)
            self.scan_finished = False
            self.data = None
            self.last_event = ""
            now = datetime.datetime.now()
            nowutc = now.now(datetime.timezone.utc)
            self.last_scan_time_epoch = now.timestamp()
            self.last_scan_time_epoch_utc = nowutc.timestamp()
            self.last_scan_time_iso = now.astimezone().isoformat(
                timespec="milliseconds"
            )
            self.last_scan_time_utc = nowutc
            self.args = args
            self.get_bssid_args = SimpleNamespace(
                get_current_ap=True,
                raw=True,
                event_watcher=True,
                get_current_channel=False,
                supported=False,
                is_bytes_arg=self.args.bytes,
            )
            self.timeout_interval = 7.0
            self.client_handle = WLAN_API.WLAN.open_handle()
            # self.scan_timer = Timer(self.timeout_interval, self.scan_timeout)
            self.scan_timer = TimerEx(self.timeout_interval, self.scan_timeout)
            self.iface = iface
            self.mac = iface.mac
            # self.first_event = True
            self.is_handle_closed = False
            self.oldepoch = time.time()
            self.callback = self.register_notification(
                self.on_event_notification, self.client_handle
            )
            callbacks.append(self.callback)
            self.log.debug("callback %s added", self.callback)
            handles.append(self.client_handle)
            self.log.debug("handle %s added", self.client_handle)
        except Exception:
            traceback.print_exc()
            WLAN_API.WLAN.close_handle(self.client_handle)

    def __del__(self):
        # callbacks.remove(self.client_handle)
        if not self.is_handle_closed:
            result = WLAN_API.WLAN.close_handle(self.client_handle)
            self.log.debug(
                "handle %s closed with result %s", self.client_handle, result
            )
            if int(result) == 0:
                self.is_handle_closed = True
            else:
                self.log.debug(
                    "problem closing %s with result", self.client_handle, result
                )

    def get_bss_list(self, interface, bytes=False) -> Union[list, None]:
        if interface:
            try:
                wireless_network_bss_list = WLAN_API.WLAN.get_wireless_network_bss_list(
                    interface, is_bytes_arg=bytes
                )

                if len(wireless_network_bss_list) == 0:
                    return None

                return wireless_network_bss_list
            except Exception:
                exception_type, exception_object, exception_traceback = sys.exc_info()
                fname = os.path.split(exception_traceback.tb_frame.f_code.co_filename)[
                    1
                ]
                self.log.error(
                    "unexpected error when trying to get the BSS list on interface with MAC %s",
                    interface.mac,
                )
                self.log.error(
                    f"{exception_object} {exception_type} {fname}:{exception_traceback.tb_lineno}"
                )
                return None
        else:
            return None

    def seconds_passed(self, oldepoch, seconds) -> bool:
        return time.time() - oldepoch >= seconds

    def on_event_notification(self, wlan_event, iface_guid) -> None:
        if self.iface.guid_string == str(iface_guid):
            pass
        else:
            return
        if wlan_event is not None:
            # attempt to get connected bssid
            bssid = get_interface_info(self.get_bssid_args, self.iface)

            # if we want to watch wlan events on the terminal
            if self.args.event_watcher:
                # if str(wlan_event).strip() in ["interface_removal", "interface_arrival"]:
                # if we want verbose info printed to the terminal
                squelch = False
                if str(wlan_event).strip() in [
                    "disconnected",
                    "profile_unblocked",
                    "radio_state_change",
                    "end",
                    "profile_change",
                ]:
                    if self.last_event == str(wlan_event).strip():
                        if self.seconds_passed(self.oldepoch, 2):
                            pass
                        else:
                            squelch = True
                    self.oldepoch = time.time()

                self.last_event = str(wlan_event).strip()
                if str(wlan_event).strip() in [
                    "scan_list_refresh",
                    "scan_complete",
                    "signal_quality_change",
                    "associating",
                    "associated",
                    "authenticating",
                    "connected",
                    "OneXNotificationTypeResultUpdate",
                    "OneXNotificationTypeAuthRestarted",
                    "connection_complete",
                    "connection_start",
                    "roaming_start",
                    "roaming_end",
                ]:
                    self.data = self.get_bss_list(self.iface, bytes=self.args.bytes)
                    bssid_data = None
                    if self.data is not None:
                        for bss in self.data:
                            if bssid == str(bss.bssid):
                                bssid_data = bss
                                break
                        rssi = ""
                        freq = ""
                        if bssid_data:
                            rssi = bssid_data.rssi
                            freq = bssid_data.channel_frequency
                        extra = ""
                        ssid = ""

                        if bssid_data:
                            ssid = bssid_data.ssid

                        if str(wlan_event).strip() in [
                            "scan_list_refresh",
                            "scan_complete",
                        ]:
                            extra = f", scan: ({len(self.data)} BSSIDs found)"
                        if not bssid:
                            msg = f"({self.mac}), event: ({wlan_event})"
                            self.log.info(msg)
                            if self.args.syslog:
                                syslog(msg, "INFO")
                        elif bssid == "00:00:00:00:00:00":
                            msg = f"({self.mac}), bssid: ({bssid}), event: ({wlan_event}){extra}"
                            self.log.info(msg)
                            if self.args.syslog:
                                syslog(msg, "INFO")
                        else:
                            msg = f"({self.mac}), bssid: ({bssid}), freq: ({freq}), ssid: ({ssid}), rssi: ({rssi}), event: ({wlan_event}){extra}"
                            self.log.info(msg)
                            if self.args.syslog:
                                syslog(msg, "INFO")
                else:
                    if not squelch:
                        if bssid:
                            msg = (
                                f"({self.mac}), bssid: ({bssid}), event: ({wlan_event})"
                            )
                            self.log.info(msg)
                            if self.args.syslog:
                                syslog(msg, "INFO")
                        else:
                            msg = f"({self.mac}), event: ({wlan_event})"
                            self.log.info(msg)
                            if self.args.syslog:
                                syslog(msg, "INFO")

            # if we're not watching for events and we want to return scan results
            if not self.args.event_watcher:
                self.log.debug(f"({self.mac}), bssid: ({bssid}), event: ({wlan_event})")

                if str(wlan_event).strip() == "scan_complete":
                    self.scan_timer.cancel()

                if str(wlan_event).strip() == "scan_fail":
                    self.log.warning(
                        f"({self.mac}), scan fail! persistent problem? reset the WLAN interface and try again ..."
                    )

                # if the list is updated, grab the results
                if str(wlan_event).strip() == "scan_list_refresh":
                    self.log.debug(f"({self.mac}), start get_bss_list...")
                    self.data = self.get_bss_list(self.iface, bytes=self.args.bytes)
                    self.scan_finished = True
                    now = datetime.datetime.now()
                    nowutc = now.now(datetime.timezone.utc)
                    self.last_scan_time_epoch = now.timestamp()
                    self.last_scan_time_epoch_utc = nowutc.timestamp()
                    self.last_scan_time_iso = now.astimezone().isoformat(
                        timespec="milliseconds"
                    )
                    self.last_scan_time_utc = nowutc
                    self.log.debug(f"({self.mac}), finish get_bss_list...")

                # if str(wlan_event).strip() == "network_available":
                #    pass

    def register_notification(self, callback, handle):
        c_back = WLAN_API.WLAN.wlan_register_notification(
            handle, functools.partial(self.on_wlan_notification, callback)
        )
        return NotificationObject(handle, c_back)

    @staticmethod
    def on_wlan_notification(callback, notification_data, p):
        event = Event.from_notification_data(notification_data)
        if event is not None:
            callback(event, notification_data.contents.InterfaceGuid)

    def my_handle(self):
        return self.client_handle

    async def scan(self):
        try:
            self.scan_finished = False
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

    def scan_timeout(self) -> None:
        """
        The application should then wait to receive the
          wlan_notification_acm_scan_complete notification or timeout after 4 seconds.
        Then the application can call the WlanGetNetworkBssList or WlanGetAvailableNetworkList
          function to retrieve a list of available wireless networks.
        """
        self.log.info(
            f"timeout interval ({self.timeout_interval} seconds) for {self.mac} exceeded..."
        )
        self.log.debug(f"({self.mac}), start get_bss_list...")
        self.data = self.get_bss_list(self.iface, bytes=self.args.bytes)
        self.log.debug(f"({self.mac}), finish get_bss_list...")
        self.scan_finished = True
