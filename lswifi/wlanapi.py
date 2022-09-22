# -*- coding: utf-8 -*-

"""
lswifi.wlanapi
~~~~~~~~~~~~~~

mostly wrapper code around Native Wifi wlanapi.h
"""

import contextlib
import logging
import sys
import threading
from ctypes import (
    c_bool,
    c_byte,
    c_char,
    c_long,
    c_ubyte,
    c_uint,
    c_ulong,
    c_ulonglong,
    c_ushort,
    c_void_p,
    c_wchar,
)
from enum import Enum
from subprocess import SubprocessError, check_output

from .guid import GUID

if sys.platform == "win32":
    from ctypes import windll
else:
    print("ERROR: win32 support only")
    sys.exit(-1)

from ctypes import CFUNCTYPE, POINTER, Structure, Union, addressof, byref, pointer
from ctypes.wintypes import BOOL, DWORD, HANDLE

from .elements import WirelessNetworkBss
from .helpers import convert_mac_address_to_string

# wlantypes.h

DOT11_SSID_MAX_LENGTH = 32
DOT11_PSD_IE_MAX_DATA_SIZE = 240
DOT11_PSD_IE_MAX_ENTRY_NUMBER = 5


class SystemErrorCodes(Enum):
    # system error codes https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes--0-499-
    ERROR_SUCCESS = 0
    ERROR_INVALID_FUNCTION = 1
    ERROR_FILE_NOT_FOUND = 2
    ERROR_INVALID_HANDLE = 6
    ERROR_NOT_ENOUGH_MEMORY = 8
    ERROR_BAD_ENVIRONMENT = 10
    ERROR_INVALID_PARAMETER = 87
    ERROR_NOT_SUPPORTED = 50
    ERROR_SERVICE_NOT_ACTIVE = 1062
    ERROR_NOT_FOUND = 1168
    ERROR_REMOTE_SESSION_LIMIT_EXCEEDED = 1220
    ERROR_NDIS_DOT11_POWER_STATE_INVALID = 0x80342002
    ERROR_INVALID_STATE = 5023


SYSTEM_ERROR_CODE_REASON = {
    0: None,
    50: "Not supported",
    5023: "The group or resource is not in the correct state to perform the requested operation.",
    2_150_899_714: "The radio associated with the interface is turned off. There are no available networks when the radio is off.",
}

# wlanapi.h

WLAN_MAX_PHY_TYPE_NUMBER = 8
DOT11_RATE_SET_MAX_LENGTH = 126
WLAN_SIGNAL_QUALITY = c_ulong

## `typedef DWORD WLAN_REASON_CODE, *PWLAN_REASON_CODE;`
WLAN_REASON_CODE = DWORD

## The DOT11_MAC_ADDRESS types are used to define an IEEE media access control
## (MAC) address: `typedef UCHAR DOT11_MAC_ADDRESS[6];`
DOT11_MAC_ADDRESS = c_ubyte * 6

WLAN_API_EXISTS = True

# load wlanapi.dll into memory
try:
    WLAN_API = windll.LoadLibrary("wlanapi.dll")
except OSError:
    WLAN_API_EXISTS = False
    print("!!! wlanapi.dll not foud !!!")

# DOT11_AUTH_ALGORITHM enumeration

""" The DOT11_AUTH_ALGORITHM enumerated type defines a wireless LAN 
authentication algorithm.

typedef enum _DOT11_AUTH_ALGORITHM { 
  DOT11_AUTH_ALGO_80211_OPEN        = 1,
  DOT11_AUTH_ALGO_80211_SHARED_KEY  = 2,
  DOT11_AUTH_ALGO_WPA               = 3,
  DOT11_AUTH_ALGO_WPA_PSK           = 4,
  DOT11_AUTH_ALGO_WPA_NONE          = 5,
  DOT11_AUTH_ALGO_RSNA              = 6,
  DOT11_AUTH_ALGO_RSNA_PSK          = 7,
  DOT11_AUTH_ALGO_IHV_START         = 0x80000000,
  DOT11_AUTH_ALGO_IHV_END           = 0xffffffff
} DOT11_AUTH_ALGORITHM, *PDOT11_AUTH_ALGORITHM;
"""
DOT11_AUTH_ALGORITHM = c_uint
DOT11_AUTH_ALGORITHM_DICT = {
    0: None,
    1: "80211_OPEN",
    2: "80211_SHARED_KEY",
    3: "WPA",
    4: "WPA_PSK",
    5: "WPA_NONE",
    6: "RSNA",
    7: "RSNA_PSK",
    0x80000000: "DOT11_AUTH_ALGO_IHV_START",
    0xFFFFFFFF: "DOT11_AUTH_ALGO_IHV_END",
}


# DOT11_BSS_TYPE enumeration

""" The DOT11_BSS_TYPE enumerated type defines a basic service set (BSS) 
network type.

typedef enum _DOT11_BSS_TYPE { 
  dot11_BSS_type_infrastructure  = 1,
  dot11_BSS_type_independent     = 2,
  dot11_BSS_type_any             = 3
} DOT11_BSS_TYPE, *PDOT11_BSS_TYPE;
"""
DOT11_BSS_TYPE = c_uint
DOT11_BSS_TYPE_DICT = {0: None, 1: "Infra.", 2: "Indep.", 3: "Any"}


# DOT11_CIPHER_ALGORITHM enumeration

""" The DOT11_CIPHER_ALGORITHM enumerated type defines a cipher algorithm for 
data encryption and decryption.

typedef enum _DOT11_CIPHER_ALGORITHM { 
  DOT11_CIPHER_ALGO_NONE           = 0x00,
  DOT11_CIPHER_ALGO_WEP40          = 0x01,
  DOT11_CIPHER_ALGO_TKIP           = 0x02,
  DOT11_CIPHER_ALGO_CCMP           = 0x04,
  DOT11_CIPHER_ALGO_WEP104         = 0x05,
  DOT11_CIPHER_ALGO_WPA_USE_GROUP  = 0x100,
  DOT11_CIPHER_ALGO_RSN_USE_GROUP  = 0x100,
  DOT11_CIPHER_ALGO_WEP            = 0x101,
  DOT11_CIPHER_ALGO_IHV_START      = 0x80000000,
  DOT11_CIPHER_ALGO_IHV_END        = 0xffffffff
} DOT11_CIPHER_ALGORITHM, *PDOT11_CIPHER_ALGORITHM;
"""
DOT11_CIPHER_ALGORITHM = c_uint
DOT11_CIPHER_ALGORITHM_DICT = {
    0: None,
    0x00: "NONE",
    0x01: "WEP40",
    0x02: "TKIP",
    0x04: "CCMP",
    0x05: "WEP104",
    0x100: "WPA_USE_GROUP",
    0x100: "RSN_USE_GROUP",
    0x101: "WEP",
    0x80000000: "DOT11_CIPHER_ALGO_IHV_START",
    0xFFFFFFFF: "DOT11_CIPHER_ALGO_IHV_END",
}


# DOT11_PHY_TYPE enumeration

""" The DOT11_PHY_TYPE enumeration defines an 802.11 PHY and media type.

typedef enum _DOT11_PHY_TYPE { 
  dot11_phy_type_unknown     = 0,
  dot11_phy_type_any         = 0,
  dot11_phy_type_fhss        = 1,
  dot11_phy_type_dsss        = 2,
  dot11_phy_type_irbaseband  = 3,
  dot11_phy_type_ofdm        = 4,
  dot11_phy_type_hrdsss      = 5,
  dot11_phy_type_erp         = 6,
  dot11_phy_type_ht          = 7,
  dot11_phy_type_vht         = 8,
  dot11_phy_type_dmg         = 9,
  dot11_phy_type_he          = 10,
  dot11_phy_type_IHV_start   = 0x80000000,
  dot11_phy_type_IHV_end     = 0xffffffff
} DOT11_PHY_TYPE, *PDOT11_PHY_TYPE;
"""
DOT11_PHY_TYPE = c_uint
DOT11_PHY_TYPE_DICT = {
    0: "unknown",  # Specifies an unknown or uninitialized PHY type.
    1: "FHSS",  # Specifies a frequency-hopping spread-spectrum (FHSS) PHY.
    2: "DSSS",  # Specifies a direct sequence spread spectrum (DSSS) PHY.
    3: "IR baseband",  # Specifies an infrared (IR) baseband PHY.
    4: "OFDM",  # Specifies an orthogonal frequency division multiplexing (OFDM) 802.11a PHY.
    5: "HR-DSSS",  # Specifies a high-rate DSSS (HRDSSS) 802.11b PHY.
    6: "ERP",  # Specifies an extended-rate 802.11g PHY (ERP).
    7: "HT",  # Specifies a high-throughput (HT) 802.11n PHY. Each 802.11n PHY, whether dual-band or not, is specified as this PHY type.
    8: "VHT",  # Specifies a very high-throughput (VHT) 802.11ac PHY.
    9: "DMG",  # Specifies a Directional Multi-Gigabit (DMG) 802.11ad PHY.
    10: "HE",  # Specifies a High Efficiency (HE) 802.11ax PHY.
    0x80000000: "dot11_phy_type_IHV_start",  # should this be 2147483648?
    0xFFFFFFFF: "dot11_phy_type_IHV_end",  # should this be 4294967295?
}


# DOT11_RADIO_STATE Enumeration

""" The DOT11_RADIO_STATE enumeration specifies an 802.11 radio state.

typedef enum _DOT11_RADIO_STATE {
  dot11_radio_state_unknown,
  dot11_radio_state_on,
  dot11_radio_state_off,
  v1_enum
} DOT11_RADIO_STATE, *PDOT11_RADIO_STATE;
"""

DOT11_RADIO_STATE = c_uint
DOT11_RADIO_STATE_DICT = {
    0: "dot11_radio_state_unknown",
    1: "dot11_radio_state_on",
    2: "dot11_radio_state_off",
}

# WLAN_CONNECTION_MODE enumeration

""" The WLAN_CONNECTION_MODE enumerated type defines the mode of connection.

typedef enum _WLAN_CONNECTION_MODE {
  wlan_connection_mode_profile,
  wlan_connection_mode_temporary_profile,
  wlan_connection_mode_discovery_secure,
  wlan_connection_mode_discovery_unsecure,
  wlan_connection_mode_auto,
  wlan_connection_mode_invalid
} WLAN_CONNECTION_MODE, *PWLAN_CONNECTION_MODE;
"""
WLAN_CONNECTION_MODE = c_uint
WLAN_CONNECTION_MODE_DICT = {
    0: "wlan_connection_mode_profile",
    1: "wlan_connection_mode_temporary_profile",
    2: "wlan_connection_mode_discovery_secure",
    3: "wlan_connection_mode_discovery_unsecure",
    4: "wlan_connection_mode_auto",
    5: "wlan_connection_mode_invalid",
}


# WLAN_INTERFACE_STATE enumeration

""" The WLAN_INTERFACE_STATE enumerated type indicates the state of an
interface.

typedef enum _WLAN_INTERFACE_STATE {
  wlan_interface_state_not_ready,
  wlan_interface_state_connected,
  wlan_interface_state_ad_hoc_network_formed,
  wlan_interface_state_disconnecting,
  wlan_interface_state_disconnected,
  wlan_interface_state_associating,
  wlan_interface_state_discovering,
  wlan_interface_state_authenticating,
  v1_enum
} WLAN_INTERFACE_STATE, *PWLAN_INTERFACE_STATE;
"""
WLAN_INTERFACE_STATE = c_uint
WLAN_INTERFACE_STATE_DICT = {
    0: "not_ready",
    1: "connected",
    2: "ad_hoc_network_formed",
    3: "disconnecting",
    4: "disconnected",
    5: "associating",
    6: "discovering",
    7: "authenticating",
}


# WLAN_INTF_OPCODE enumeration

""" The WLAN_INTF_OPCODE enumerated type defines various opcodes used
to set and query parameters on a wireless interface.

typedef enum _WLAN_INTF_OPCODE {
  wlan_intf_opcode_autoconf_start,
  wlan_intf_opcode_autoconf_enabled,
  wlan_intf_opcode_background_scan_enabled,
  wlan_intf_opcode_media_streaming_mode,
  wlan_intf_opcode_radio_state,
  wlan_intf_opcode_bss_type,
  wlan_intf_opcode_interface_state,
  wlan_intf_opcode_current_connection,
  wlan_intf_opcode_channel_number,
  wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
  wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,
  wlan_intf_opcode_supported_country_or_region_string_list,
  wlan_intf_opcode_current_operation_mode,
  wlan_intf_opcode_supported_safe_mode,
  wlan_intf_opcode_certified_safe_mode,
  wlan_intf_opcode_hosted_network_capable,
  wlan_intf_opcode_management_frame_protection_capable,
  wlan_intf_opcode_autoconf_end,
  wlan_intf_opcode_msm_start,
  wlan_intf_opcode_statistics,
  wlan_intf_opcode_rssi,
  wlan_intf_opcode_msm_end,
  wlan_intf_opcode_security_start,
  wlan_intf_opcode_security_end,
  wlan_intf_opcode_ihv_start,
  wlan_intf_opcode_ihv_end,
  v1_enum
} WLAN_INTF_OPCODE, *PWLAN_INTF_OPCODE;
"""
WLAN_INTF_OPCODE = c_uint
WLAN_INTF_OPCODE_DICT = {
    0x000000000: "wlan_intf_opcode_autoconf_start",
    1: "wlan_intf_opcode_autoconf_enabled",
    2: "wlan_intf_opcode_background_scan_enabled",
    3: "wlan_intf_opcode_media_streaming_mode",
    4: "wlan_intf_opcode_radio_state",
    5: "wlan_intf_opcode_bss_type",
    6: "wlan_intf_opcode_interface_state",
    7: "wlan_intf_opcode_current_connection",
    8: "wlan_intf_opcode_channel_number",
    9: "wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs",
    10: "wlan_intf_opcode_supported_adhoc_auth_cipher_pairs",
    11: "wlan_intf_opcode_supported_country_or_region_string_list",
    12: "wlan_intf_opcode_current_operation_mode",
    13: "wlan_intf_opcode_supported_safe_mode",
    14: "wlan_intf_opcode_certified_safe_mode",
    15: "wlan_intf_opcode_hosted_network_capable",
    16: "wlan_intf_opcode_management_frame_protection_capable",
    0x0FFFFFFF: "wlan_intf_opcode_autoconf_end",
    0x10000100: "wlan_intf_opcode_msm_start",
    17: "wlan_intf_opcode_statistics",
    18: "wlan_intf_opcode_rssi",
    0x1FFFFFFF: "wlan_intf_opcode_msm_end",
    0x20010000: "wlan_intf_opcode_security_start",
    0x2FFFFFFF: "wlan_intf_opcode_security_end",
    0x30000000: "wlan_intf_opcode_ihv_start",
    0x3FFFFFFF: "wlan_intf_opcode_ihv_end",
}


# WLAN_OPCODE_VALUE_TYPE Enumeration

""" The WLAN_OPCODE_VALUE_TYPE enumeration specifies the origin of automatic 
configuration (auto config) settings.

typedef enum _WLAN_OPCODE_VALUE_TYPE {
  wlan_opcode_value_type_query_only,
  wlan_opcode_value_type_set_by_group_policy,
  wlan_opcode_value_type_set_by_user,
  wlan_opcode_value_type_invalid,
  v1_enum
} WLAN_OPCODE_VALUE_TYPE, *PWLAN_OPCODE_VALUE_TYPE;
"""
WLAN_OPCODE_VALUE_TYPE = c_uint
WLAN_OPCODE_VALUE_TYPE_DICT = {
    0: "wlan_opcode_value_type_query_only",
    1: "wlan_opcode_value_type_set_by_group_policy",
    2: "wlan_opcode_value_type_set_by_user",
    3: "wlan_opcode_value_type_invalid",
    4: "v1_enum",
}


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


class DOT11SSID(Structure):
    """A DOT11_SSID structure contains the SSID of an interface.

    typedef struct _DOT11_SSID {
    ULONG uSSIDLength;
    UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
    } DOT11_SSID, *PDOT11_SSID;
    """

    _fields_ = [("SSIDLength", c_ulong), ("SSID", c_char * DOT11_SSID_MAX_LENGTH)]


class WLANAssociationAttributes(Structure):
    """The WLAN_ASSOCIATION_ATTRIBUTES structure contains association
    attributes for a connection.

    typedef struct _WLAN_ASSOCIATION_ATTRIBUTES {
      DOT11_SSID          dot11Ssid;
      DOT11_BSS_TYPE      dot11BssType;
      DOT11_MAC_ADDRESS   dot11Bssid;
      DOT11_PHY_TYPE      dot11PhyType;
      ULONG               uDot11PhyIndex;
      WLAN_SIGNAL_QUALITY wlanSignalQuality;
      ULONG               ulRxRate;
      ULONG               ulTxRate;
    } WLAN_ASSOCIATION_ATTRIBUTES, *PWLAN_ASSOCIATION_ATTRIBUTES;
    """

    _fields_ = [
        ("dot11Ssid", DOT11SSID),
        ("dot11BssType", DOT11_BSS_TYPE),
        ("dot11Bssid", DOT11_MAC_ADDRESS),
        ("dot11PhyType", DOT11_PHY_TYPE),
        ("uDot11PhyIndex", c_ulong),
        ("wlanSignalQuality", WLAN_SIGNAL_QUALITY),
        ("ulRxRate", c_ulong),
        ("ulTxRate", c_ulong),
    ]


class WLANSecurityAttributes(Structure):
    """The WLAN_SECURITY_ATTRIBUTES structure defines the security attributes
    for a wireless connection.

    typedef struct _WLAN_SECURITY_ATTRIBUTES {
      BOOL                   bSecurityEnabled;
      BOOL                   bOneXEnabled;
      DOT11_AUTH_ALGORITHM   dot11AuthAlgorithm;
      DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
    } WLAN_SECURITY_ATTRIBUTES, *PWLAN_SECURITY_ATTRIBUTES;
    """

    _fields_ = [
        ("bSecurityEnabled", BOOL),
        ("bOneXEnabled", BOOL),
        ("dot11AuthAlgorithm", DOT11_AUTH_ALGORITHM),
        ("dot11CipherAlgorithm", DOT11_CIPHER_ALGORITHM),
    ]


class WLANAvailableNetwork(Structure):
    """
    The WLAN_AVAILABLE_NETWORK structure contains information about an
    available wireless network.

    typedef struct _WLAN_AVAILABLE_NETWORK {
      WCHAR                  strProfileName[WLAN_MAX_NAME_LENGTH];
      DOT11_SSID             dot11Ssid;
      DOT11_BSS_TYPE         dot11BssType;
      ULONG                  uNumberOfBssids;
      BOOL                   bNetworkConnectable;
      WLAN_REASON_CODE       wlanNotConnectableReason;
      ULONG                  uNumberOfPhyTypes;
      DOT11_PHY_TYPE         dot11PhyTypes[WLAN_MAX_PHY_TYPE_NUMBER];
      BOOL                   bMorePhyTypes;
      WLAN_SIGNAL_QUALITY    wlanSignalQuality;
      BOOL                   bSecurityEnabled;
      DOT11_AUTH_ALGORITHM   dot11DefaultAuthAlgorithm;
      DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
      DWORD                  dwFlags;
      DWORD                  dwReserved;
    } WLAN_AVAILABLE_NETWORK, *PWLAN_AVAILABLE_NETWORK;
    """

    _fields_ = [
        ("ProfileName", c_wchar * 256),
        ("dot11Ssid", DOT11SSID),
        ("dot11BssType", DOT11_BSS_TYPE),
        ("NumberOfBssids", c_ulong),
        ("NetworkConnectable", c_bool),
        ("wlanNotConnectableReason", WLAN_REASON_CODE),
        ("NumberOfPhyTypes", c_ulong),
        ("dot11PhyTypes", DOT11_PHY_TYPE * WLAN_MAX_PHY_TYPE_NUMBER),
        ("MorePhyTypes", c_bool),
        ("wlanSignalQuality", WLAN_SIGNAL_QUALITY),
        ("SecurityEnabled", c_bool),
        ("dot11DefaultAuthAlgorithm", DOT11_AUTH_ALGORITHM),
        ("dot11DefaultCipherAlgorithm", DOT11_CIPHER_ALGORITHM),
        ("Flags", DWORD),
        ("Reserved", DWORD),
    ]


class WLANAvailableNetworkList(Structure):
    """
    The WLAN_AVAILABLE_NETWORK_LIST structure contains an array of information
    about available networks.

    typedef struct _WLAN_AVAILABLE_NETWORK_LIST {
      DWORD                  dwNumberOfItems;
      DWORD                  dwIndex;
    #if ...
      WLAN_AVAILABLE_NETWORK *Network[];
    #else
      WLAN_AVAILABLE_NETWORK Network[1];
    #endif
    } WLAN_AVAILABLE_NETWORK_LIST, *PWLAN_AVAILABLE_NETWORK_LIST;
    """

    _fields_ = [
        ("NumberOfItems", DWORD),
        ("Index", DWORD),
        ("Network", WLANAvailableNetwork * 1),
    ]


class WLANRateSet(Structure):
    """The set of supported data rates.

    Minimum supported client: Windows Vista [desktop apps only]
    Header: wlanapi.h

    class WLAN_RATE_SET(Structure):
        _fields_ = [
            ("RateSetLength", c_ulong),
            ("RateSet", c_ushort * DOT11_RATE_SET_MAX_LENGTH),
        ]

    To calculate the data transfer rate in Mbps for an arbitrary array entry rateSet[i], use the following equation:

    rate_to_mbps = (rateSet[i] & 0x7FFF) * 0.5
    """

    _fields_ = [
        ("RateSetLength", c_ulong),
        ("RateSet", c_ushort * DOT11_RATE_SET_MAX_LENGTH),
    ]


class WLANBSSEntry(Structure):
    """The WLAN_BSS_ENTRY structure contains information about a basic service set (BSS).

    Minimum supported client: Windows Vista [desktop apps only]
    Header: wlanapi.h

    typedef struct _WLAN_BSS_ENTRY {
    DOT11_SSID        dot11Ssid;
    ULONG             uPhyId;
    DOT11_MAC_ADDRESS dot11Bssid;
    DOT11_BSS_TYPE    dot11BssType;
    DOT11_PHY_TYPE    dot11BssPhyType;
    LONG              lRssi;
    ULONG             uLinkQuality;
    BOOLEAN           bInRegDomain;
    USHORT            usBeaconPeriod;
    ULONGLONG         ullTimestamp;
    ULONGLONG         ullHostTimestamp;
    USHORT            usCapabilityInformation;
    ULONG             ulChCenterFrequency;
    WLAN_RATE_SET     wlanRateSet;
    ULONG             ulIeOffset;
    ULONG             ulIeSize;
    } WLAN_BSS_ENTRY, *PWLAN_BSS_ENTRY;
    """

    def send(self):
        """
        copy bytes from a ctypes structure
        :return:
        """
        return bytes(self)

    _fields_ = [
        ("dot11Ssid", DOT11SSID),
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
    ]


class WLANBSSList(Structure):
    """The WLAN_BSS_LIST structure contains a list of basic service set (BSS) entries.

    Minimum supported client: Windows Vista, Windows XP with SP3 [desktop apps only]
    Header: wlanapi.h

    typedef struct _WLAN_BSS_LIST {
    DWORD          dwTotalSize;
    DWORD          dwNumberOfItems;
    WLAN_BSS_ENTRY wlanBssEntries[1];
    } WLAN_BSS_LIST, *PWLAN_BSS_LIST;
    """

    _fields_ = [
        ("TotalSize", DWORD),
        ("NumberOfItems", DWORD),
        ("wlanBssEntries", WLANBSSEntry * 1),
    ]


class WLANConnectionAttributes(Structure):
    """
    The WLAN_CONNECTION_ATTRIBUTES structure defines the attributes of a
    wireless connection.

    typedef struct _WLAN_CONNECTION_ATTRIBUTES {
      WLAN_INTERFACE_STATE        isState;
      WLAN_CONNECTION_MODE        wlanConnectionMode;
      WCHAR                       strProfileName[WLAN_MAX_NAME_LENGTH];
      WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
      WLAN_SECURITY_ATTRIBUTES    wlanSecurityAttributes;
    } WLAN_CONNECTION_ATTRIBUTES, *PWLAN_CONNECTION_ATTRIBUTES;
    """

    _fields_ = [
        ("isState", WLAN_INTERFACE_STATE),
        ("wlanConnectionMode", WLAN_CONNECTION_MODE),
        ("strProfileName", c_wchar * 256),
        ("wlanAssociationAttributes", WLANAssociationAttributes),
        ("wlanSecurityAttributes", WLANSecurityAttributes),
    ]


class WLANInterfaceInfo(Structure):
    """The WLAN_INTERFACE_INFO structure contains information about a wireless LAN interface.

    Minimum supported client: Windows Vista, Windows XP with SP3
    Header: wlanapi.h

    typedef struct _WLAN_INTERFACE_INFO {
    GUID                 InterfaceGuid;
    WCHAR                strInterfaceDescription[WLAN_MAX_NAME_LENGTH];
    WLAN_INTERFACE_STATE isState;
    } WLAN_INTERFACE_INFO, *PWLAN_INTERFACE_INFO;
    """

    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", c_wchar * 256),
        ("isState", WLAN_INTERFACE_STATE),
    ]


class WLANInterfaceInfoList(Structure):
    """The WLAN_INTERFACE_INFO_LIST structure contains an array of NIC interface information.

    Minimum supported client: Windows Vista, Windows XP with SP3
    Header: wlanapi.h

    typedef struct _WLAN_INTERFACE_INFO_LIST {
    DWORD               dwNumberOfItems;
    DWORD               dwIndex;
    #if ...
    WLAN_INTERFACE_INFO *InterfaceInfo[];
    #else
    WLAN_INTERFACE_INFO InterfaceInfo[1];
    #endif
    } WLAN_INTERFACE_INFO_LIST, *PWLAN_INTERFACE_INFO_LIST;
    """

    _fields_ = [
        ("NumberOfItems", DWORD),
        ("Index", DWORD),
        ("InterfaceInfo", WLANInterfaceInfo * 1),
    ]


class WLANPHYRadioState(Structure):
    """The WLAN_PHY_RADIO_STATE structure specifies the radio state on a specific physical
    layer (PHY) type.

    typedef struct _WLAN_PHY_RADIO_STATE {
      DWORD             dwPhyIndex;
      DOT11_RADIO_STATE dot11SoftwareRadioState;
      DOT11_RADIO_STATE dot11HardwareRadioState;
    } WLAN_PHY_RADIO_STATE, *PWLAN_PHY_RADIO_STATE;
    """

    _fields_ = [
        ("dwPhyIndex", DWORD),
        ("dot11SoftwareRadioState", DOT11_RADIO_STATE),
        ("dot11HardwareRadioState", DOT11_RADIO_STATE),
    ]


class WLANRadioState(Structure):
    """The WLAN_RADIO_STATE structure specifies the radio state on a list of physical
    layer (PHY) types.

    typedef struct _WLAN_RADIO_STATE {
      DWORD                dwNumberOfPhys;
      WLAN_PHY_RADIO_STATE PhyRadioState[WLAN_MAX_PHY_INDEX];
    } WLAN_RADIO_STATE, *PWLAN_RADIO_STATE;
    """

    _fields_ = [("dwNumberOfPhys", DWORD), ("PhyRadioState", WLANPHYRadioState * 64)]


class WLANMACFrameStatistics(Structure):
    """
    typedef struct WLAN_MAC_FRAME_STATISTICS {
      ULONGLONG ullTransmittedFrameCount;
      ULONGLONG ullReceivedFrameCount;
      ULONGLONG ullWEPExcludedCount;
      ULONGLONG ullTKIPLocalMICFailures;
      ULONGLONG ullTKIPReplays;
      ULONGLONG ullTKIPICVErrorCount;
      ULONGLONG ullCCMPReplays;
      ULONGLONG ullCCMPDecryptErrors;
      ULONGLONG ullWEPUndecryptableCount;
      ULONGLONG ullWEPICVErrorCount;
      ULONGLONG ullDecryptSuccessCount;
      ULONGLONG ullDecryptFailureCount;
    } WLAN_MAC_FRAME_STATISTICS, *PWLAN_MAC_FRAME_STATISTICS;
    """

    _fields_ = [
        ("TransmittedFrameCount", c_ulonglong),
        ("ReceivedFrameCount", c_ulonglong),
        ("WEPExcludedCount", c_ulonglong),
        ("TKIPLocalMICFailures", c_ulonglong),
        ("TKIPReplays", c_ulonglong),
        ("TKIPICVErrorCount", c_ulonglong),
        ("CCMPReplays", c_ulonglong),
        ("CCMPDecryptErrors", c_ulonglong),
        ("WEPUndecryptableCount", c_ulonglong),
        ("WEPICVErrorCount", c_ulonglong),
        ("DecryptSuccessCount", c_ulonglong),
        ("DecryptFailureCount", c_ulonglong),
    ]


class WLANStatistics(Structure):
    """
    typedef struct WLAN_STATISTICS {
     ULONGLONG                 ullFourWayHandshakeFailures;
     ULONGLONG                 ullTKIPCounterMeasuresInvoked;
     ULONGLONG                 ullReserved;
     WLAN_MAC_FRAME_STATISTICS MacUcastCounters;
     WLAN_MAC_FRAME_STATISTICS MacMcastCounters;
     DWORD                     dwNumberOfPhys;
    #if ...
     WLAN_PHY_FRAME_STATISTICS *PhyCounters[];
    #else
     WLAN_PHY_FRAME_STATISTICS PhyCounters[1];
    #endif
    } WLAN_STATISTICS, *PWLAN_STATISTICS;
    """

    _fields_ = [
        ("FourWayHandshakeFailures", c_ulonglong),
        ("TKIPCounterMeasuresInvoked", c_ulonglong),
        ("Reserved", c_ulonglong),
        ("MacUcastCounters", WLANMACFrameStatistics),
        ("MacMcastCounters", WLANMACFrameStatistics),
        ("NumberOfPhys", DWORD),
    ]


WLAN_INTF_OPCODE_TYPE_DICT = {
    "wlan_intf_opcode_autoconf_enabled": c_bool,
    "wlan_intf_opcode_background_scan_enabled": c_bool,
    "wlan_intf_opcode_radio_state": WLANRadioState,
    "wlan_intf_opcode_bss_type": DOT11_BSS_TYPE,
    "wlan_intf_opcode_interface_state": WLAN_INTERFACE_STATE,
    "wlan_intf_opcode_current_connection": WLANConnectionAttributes,
    "wlan_intf_opcode_channel_number": c_ulong,
    # "wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs": \
    # WLAN_AUTH_CIPHER_PAIR_LIST,
    # "wlan_intf_opcode_supported_adhoc_auth_cipher_pairs": \
    # WLAN_AUTH_CIPHER_PAIR_LIST,
    # "wlan_intf_opcode_supported_country_or_region_string_list": \
    # WLAN_COUNTRY_OR_REGION_STRING_LIST,
    "wlan_intf_opcode_media_streaming_mode": c_bool,
    "wlan_intf_opcode_statistics": WLANStatistics,
    "wlan_intf_opcode_rssi": c_long,
    "wlan_intf_opcode_current_operation_mode": c_ulong,
    "wlan_intf_opcode_supported_safe_mode": c_bool,
    "wlan_intf_opcode_certified_safe_mode": c_bool,
}


class WLANRawDataList(Structure):
    """The WLAN_RAW_DATA_LIST structure contains raw data in the form of an array
     of data blobs that are used by some Native Wifi functions.

    typedef struct _WLAN_RAW_DATA_LIST {
      DWORD                   dwTotalSize;
      DWORD                   dwNumberOfItems;
      struct {
        DWORD dwDataOffset;
        DWORD dwDataSize;
      };
      __unnamed_struct_05e4_1 DataList[1];
    } WLAN_RAW_DATA_LIST, *PWLAN_RAW_DATA_LIST;
    """

    _fields_ = [("TotalSize", DWORD), ("NumberOfItems", DWORD)]


class WLANRawData(Structure):
    """The WLAN_RAW_DATA structure contains raw data in the form of a blob that is
    used by some Native Wifi functions.

    The WLAN_RAW_DATA structure is a raw data structure used to hold a data entry used by
      some Native Wifi functions.
    The data structure is in the form of a generalized blob that can contain any type of data.

    The WlanScan function uses the WLAN_RAW_DATA structure.

    The pIeData parameter passed to the WlanScan function points to a WLAN_RAW_DATA structure
      currently used to contain an information element to include in probe requests.
    This WLAN_RAW_DATA structure passed to the WlanScan function can contain a
      proximity service discovery (PSD) information element (IE) data entry.

    When the WLAN_RAW_DATA structure is used to store a PSD IE,
      the DOT11_PSD_IE_MAX_DATA_SIZE constant defined in the Wlanapi.h header file
      is the maximum value of the dwDataSize member.

    typedef struct _WLAN_RAW_DATA {
      DWORD dwDataSize;
    #if ...
      BYTE  *DataBlob[];
    #else
      BYTE  DataBlob[1];
    #endif
    } WLAN_RAW_DATA, *PWLAN_RAW_DATA;
    """

    _fields_ = [("DataSize", DWORD), ("DataBlob", c_byte * 1)]


class InformationElement(
    object
):  # TODO: MOVE THIS TO ELEMENTS.PY DOES NOT BELONG IN WLANAPI
    """Data class for an 802.11 Information Element"""

    def __init__(self, eid, name, length, decoded, body, pbody):
        self.eid = eid
        self.name = name
        self.length = length
        self.decoded = decoded
        self.body = body
        self.pbody = pbody

    def __str__(self):
        return "Element ID: {}\nName: {}\nLength: {}\nDecoded: {}\nBody: {}\nPretty Body: {}".format(
            self.eid, self.name, self.length, self.decoded, self.body, self.pbody
        )


class WirelessInterface(object):
    """Data class for the wireless interface"""

    def __init__(self, wlan_iface_info):
        self.log = logging.getLogger(__name__)
        self.description = wlan_iface_info.strInterfaceDescription
        self.guid = GUID(wlan_iface_info.InterfaceGuid)
        self.guid_string = str(wlan_iface_info.InterfaceGuid)
        self.state = wlan_iface_info.isState
        self.state_string = WLAN_INTERFACE_STATE_DICT.get(self.state, 0)
        self.map_guid_to_mac_and_connection_name(self.guid, self.description)

    def map_guid_to_mac_and_connection_name(self, guid, description) -> None:
        guid = str(guid)[1:-1]  # remove { } around guid
        exe = 'getmac.exe /FO "CSV" /V'  # use getmac.exe to map interface guid to mac
        cmd = f"{exe}"
        try:
            output = check_output(cmd)
            mac = ""
            self.log.debug(
                "checking output from '%s' to do a lookup on given guid for matching MAC and connection name",
                exe,
            )
            for line in output.decode().splitlines():
                if guid in line or description in line:
                    connection = line.split(",")
                    mac = connection[2].replace('"', "")
                    self.mac = mac.lower().replace("-", ":")
                    self.connection_name = connection[0].replace('"', "")
                    self.log.debug(
                        f"guid {guid} maps to {self.mac} and {self.connection_name}"
                    )
                    break
        except SubprocessError as error:
            print(error)

    def __str__(self):
        return f"Interface: {self.__dict__}"


# WLAN_NOTIFICATION_ACM enumeration
"""
typedef enum _WLAN_NOTIFICATION_ACM {
  wlan_notification_acm_start,
  wlan_notification_acm_autoconf_enabled,
  wlan_notification_acm_autoconf_disabled,
  wlan_notification_acm_background_scan_enabled,
  wlan_notification_acm_background_scan_disabled,
  wlan_notification_acm_bss_type_change,
  wlan_notification_acm_power_setting_change,
  wlan_notification_acm_scan_complete,
  wlan_notification_acm_scan_fail,
  wlan_notification_acm_connection_start,
  wlan_notification_acm_connection_complete,
  wlan_notification_acm_connection_attempt_fail,
  wlan_notification_acm_filter_list_change,
  wlan_notification_acm_interface_arrival,
  wlan_notification_acm_interface_removal,
  wlan_notification_acm_profile_change,
  wlan_notification_acm_profile_name_change,
  wlan_notification_acm_profiles_exhausted,
  wlan_notification_acm_network_not_available,
  wlan_notification_acm_network_available,
  wlan_notification_acm_disconnecting,
  wlan_notification_acm_disconnected,
  wlan_notification_acm_adhoc_network_state_change,
  wlan_notification_acm_profile_unblocked,
  wlan_notification_acm_screen_power_change,
  wlan_notification_acm_profile_blocked,
  wlan_notification_acm_scan_list_refresh,
  wlan_notification_acm_operational_state_change,
  wlan_notification_acm_end,
  v1_enum
} WLAN_NOTIFICATION_ACM, *PWLAN_NOTIFICATION_ACM;
"""
WLAN_NOTIFICATION_SOURCE_ACM_DICT = {
    0x00000001: "Autoconfig_Enabled",
    0x00000002: "Autoconfig_Disabled",
    0x00000003: "Background_Scan_Enabled",
    0x00000004: "Background_Scan_Disabled",
    0x00000005: "Bss_Type_Change",
    0x00000006: "Power_Setting_Change",
    0x00000007: "Scan_Complete",
    0x00000008: "Scan_Fail",
    0x00000009: "Connection_Start",
    0x0000000A: "Connection_Complete",
    0x0000000B: "Connection_AttemptFail",
    0x0000000C: "Filter_List_Change",
    0x0000000D: "Interface_Arrival",
    0x0000000E: "Interface_Removal",
    0x0000000F: "Profile_Change",
    0x00000010: "Profile_Name_Change",
    0x00000011: "Profiles_Exhausted",
    0x00000012: "Network_Not_Available",
    0x00000013: "Network_Available",
    0x00000014: "Disconnecting",
    0x00000015: "Disconnected",
    0x00000016: "Adhoc_Network_State_Change",
    0x00000017: "Profile_Unblocked",
    0x00000018: "Screen_Power_Change",
    0x00000019: "Profile_Blocked",
    0x0000001A: "Scan_List_Refresh",
}


class WLANNotificationData(Structure):
    """The WLAN_NOTIFICATION_DATA structure contains information provided
    when receiving notifications.

    typedef struct _WLAN_NOTIFICATION_DATA {
      DWORD NotificationSource;
      DWORD NotificationCode;
      GUID  InterfaceGuid;
      DWORD dwDataSize;
      PVOID pData;
    } WLAN_NOTIFICATION_DATA, *PWLAN_NOTIFICATION_DATA;
    """

    _fields_ = [
        ("NotificationSource", DWORD),
        ("NotificationCode", DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", DWORD),
        ("pData", c_void_p),
    ]

    # class WLANNotificationCallback(Structure):
    """
    WLAN_NOTIFICATION_CALLBACK WlanNotificationCallback;

    void WlanNotificationCallback(
      PWLAN_NOTIFICATION_DATA Arg1,
      PVOID Arg2
    )
    {...}
    """


# WLAN Notification Registration Flags
WLAN_NOTIFICATION_SOURCE_NONE = 0x0000
WLAN_NOTIFICATION_SOURCE_ONEX = 0x0004
WLAN_NOTIFICATION_SOURCE_ACM = 0x0008
WLAN_NOTIFICATION_SOURCE_MSM = 0x0010
WLAN_NOTIFICATION_SOURCE_SECURITY = 0x0020
WLAN_NOTIFICATION_SOURCE_IHV = 0x0040
WLAN_NOTIFICATION_SOURCE_HNWK = 0x0080
WLAN_NOTIFICATION_SOURCE_ALL = 0xFFFF


WLAN_NOTIFICATION_SOURCE_DICT = {
    WLAN_NOTIFICATION_SOURCE_NONE: "WLAN_NOTIFICATION_SOURCE_NONE",
    WLAN_NOTIFICATION_SOURCE_ONEX: "WLAN_NOTIFICATION_SOURCE_ONEX",
    WLAN_NOTIFICATION_SOURCE_ACM: "WLAN_NOTIFICATION_SOURCE_ACM",
    WLAN_NOTIFICATION_SOURCE_MSM: "WLAN_NOTIFICATION_SOURCE_MSM",
    WLAN_NOTIFICATION_SOURCE_SECURITY: "WLAN_NOTIFICATION_SOURCE_SECURITY",
    WLAN_NOTIFICATION_SOURCE_IHV: "WLAN_NOTIFICATION_SOURCE_IHV",
    WLAN_NOTIFICATION_SOURCE_HNWK: "WLAN_NOTIFICATION_SOURCE_HNWK",
    WLAN_NOTIFICATION_SOURCE_ALL: "WLAN_NOTIFICATION_SOURCE_ALL",
}


class ONEX_NOTIFICATION_TYPE_ENUM(Enum):
    """The ONEX_NOTIFICATION_TYPE enumerated type specifies the possible values of the
     NotificationCode member of the WLAN_NOTIFICATION_DATA structure for 802.1X module notifications.

    typedef enum _ONEX_NOTIFICATION_TYPE {
      OneXPublicNotificationBase,
      OneXNotificationTypeResultUpdate,
      OneXNotificationTypeAuthRestarted,
      OneXNotificationTypeEventInvalid,
      OneXNumNotifications
    } ONEX_NOTIFICATION_TYPE, PONEX_NOTIFICATION_TYPE;
    """

    OneXPublicNotificationBase = 0
    OneXNotificationTypeResultUpdate = 1
    OneXNotificationTypeAuthRestarted = 2
    OneXNotificationTypeEventInvalid = 3
    OneXNumNotifications = OneXNotificationTypeEventInvalid


class WLAN_NOTIFICATION_MSM_ENUM(Enum):
    """The WLAN_NOTIFICATION_MSM enumerated type specifies the possible values of the
    NotificationCode member of the WLAN_NOTIFICATION_DATA structure for Media Specific Module (MSM) notifications.

    typedef enum _WLAN_NOTIFICATION_MSM {
      wlan_notification_msm_start,
      wlan_notification_msm_associating,
      wlan_notification_msm_associated,
      wlan_notification_msm_authenticating,
      wlan_notification_msm_connected,
      wlan_notification_msm_roaming_start,
      wlan_notification_msm_roaming_end,
      wlan_notification_msm_radio_state_change,
      wlan_notification_msm_signal_quality_change,
      wlan_notification_msm_disassociating,
      wlan_notification_msm_disconnected,
      wlan_notification_msm_peer_join,
      wlan_notification_msm_peer_leave,
      wlan_notification_msm_adapter_removal,
      wlan_notification_msm_adapter_operation_mode_change,
      wlan_notification_msm_link_degraded,
      wlan_notification_msm_link_improved,
      wlan_notification_msm_end,
      v1_enum
    } WLAN_NOTIFICATION_MSM, *PWLAN_NOTIFICATION_MSM;
    """

    start = 0
    associating = 1
    associated = 2
    authenticating = 3
    connected = 4
    roaming_start = 5
    roaming_end = 6
    radio_state_change = 7
    signal_quality_change = 8
    disassociating = 9
    disconnected = 10
    peer_join = 11
    peer_leave = 12
    adapter_removal = 13
    adapter_operation_mode_change = 14
    end = 15


class WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM(Enum):
    wlan_hosted_network_state_change = 4096
    wlan_hosted_network_peer_state_change = 4097
    wlan_hosted_network_radio_state_change = 4098


class WLAN_CONNECTION_NOTIFICATION_DATA(Structure):
    """
    typedef struct _WLAN_CONNECTION_NOTIFICATION_DATA {
      WLAN_CONNECTION_MODE wlanConnectionMode;
      WCHAR                strProfileName[WLAN_MAX_NAME_LENGTH];
      DOT11_SSID           dot11Ssid;
      DOT11_BSS_TYPE       dot11BssType;
      BOOL                 bSecurityEnabled;
      WLAN_REASON_CODE     wlanReasonCode;
      DWORD                dwFlags;
      WCHAR                strProfileXml[1];
    } WLAN_CONNECTION_NOTIFICATION_DATA, *PWLAN_CONNECTION_NOTIFICATION_DATA;
    """

    _fields_ = [
        ("wlanConnectionMode", WLAN_CONNECTION_MODE),
        ("strProfileName", c_wchar * 256),
        ("dot11Ssid", DOT11SSID),
        ("dot11BssType", DOT11_BSS_TYPE),
        ("bSecurityEnabled", BOOL),
        ("wlanReasonCode", WLAN_REASON_CODE),
        ("dwFlags", DWORD),
        ("strProfileXml", (c_wchar * 1)),
    ]


class WLAN_MSM_NOTIFICATION_DATA(Structure):
    """The WLAN_MSM_NOTIFICATION_DATA structure contains information about media specific
    module (MSM) connection related notifications.

    typedef struct _WLAN_MSM_NOTIFICATION_DATA {
      WLAN_CONNECTION_MODE wlanConnectionMode;
      WCHAR                strProfileName[WLAN_MAX_NAME_LENGTH];
      DOT11_SSID           dot11Ssid;
      DOT11_BSS_TYPE       dot11BssType;
      DOT11_MAC_ADDRESS    dot11MacAddr;
      BOOL                 bSecurityEnabled;
      BOOL                 bFirstPeer;
      BOOL                 bLastPeer;
      WLAN_REASON_CODE     wlanReasonCode;
    } WLAN_MSM_NOTIFICATION_DATA, *PWLAN_MSM_NOTIFICATION_DATA;
    """

    _fields_ = [
        ("wlanConnectionMode", WLAN_CONNECTION_MODE),
        ("strProfileName", c_wchar * 256),
        ("dot11Ssid", DOT11SSID),
        ("dot11BssType", DOT11_BSS_TYPE),
        ("dot11MacAddr", DOT11_MAC_ADDRESS),
        ("bSecurityEnabled", BOOL),
        ("bFirstPeer", BOOL),
        ("bLastPeer", BOOL),
        ("wlanReasonCode", WLAN_REASON_CODE),
    ]


class WLAN_NOTIFICATION_ACM_ENUM(Enum):
    start = 0
    autoconf_enabled = 1
    autoconf_disabled = 2
    background_scan_enabled = 3
    background_scan_disabled = 4
    bss_type_change = 5
    power_setting_change = 6
    scan_complete = 7
    scan_fail = 8
    connection_start = 9
    connection_complete = 10
    connection_attempt_fail = 11
    filter_list_change = 12
    interface_arrival = 13
    interface_removal = 14
    profile_change = 15
    profile_name_change = 16
    profiles_exhausted = 17
    network_not_available = 18
    network_available = 19
    disconnecting = 20
    disconnected = 21
    adhoc_network_state_change = 22
    profile_unblocked = 23
    screen_power_change = 24
    profile_blocked = 25
    scan_list_refresh = 26
    end = 27


WLAN_NOTIFICATION_DATA_ACM_TYPES_DICT = {
    WLAN_NOTIFICATION_ACM_ENUM.autoconf_enabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.autoconf_disabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.background_scan_enabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.background_scan_disabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.bss_type_change: DOT11_BSS_TYPE,
    WLAN_NOTIFICATION_ACM_ENUM.power_setting_change: None,  # TODO: Change to WLAN_POWER_SETTING
    WLAN_NOTIFICATION_ACM_ENUM.scan_complete: None,
    WLAN_NOTIFICATION_ACM_ENUM.scan_fail: WLAN_REASON_CODE,
    WLAN_NOTIFICATION_ACM_ENUM.connection_start: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.connection_complete: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.connection_attempt_fail: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.filter_list_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.interface_arrival: None,
    WLAN_NOTIFICATION_ACM_ENUM.interface_removal: None,
    WLAN_NOTIFICATION_ACM_ENUM.profile_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.profile_name_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.profiles_exhausted: None,
    WLAN_NOTIFICATION_ACM_ENUM.network_not_available: None,
    WLAN_NOTIFICATION_ACM_ENUM.network_available: None,
    WLAN_NOTIFICATION_ACM_ENUM.disconnecting: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.disconnected: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.adhoc_network_state_change: None,  # TODO: Change to WLAN_ADHOC_NETWORK_STATE
    WLAN_NOTIFICATION_ACM_ENUM.profile_unblocked: None,
    WLAN_NOTIFICATION_ACM_ENUM.screen_power_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.profile_blocked: None,
    WLAN_NOTIFICATION_ACM_ENUM.scan_list_refresh: None,
}


class WLANNotificationSource(Enum):
    ACM = 8
    ALL = 65535  # 0x0000FFFF
    IHV = 64  # 0x00000040
    MSM = 16  # 0x00000010
    NONE = None
    SECURITY = 32  # 0x00000020


WLAN_NOTIFICATION_DATA_MSM_TYPES_DICT = {
    WLAN_NOTIFICATION_MSM_ENUM.associating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.associated: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.authenticating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.connected: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.roaming_start: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.roaming_end: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.radio_state_change: None,
    WLAN_NOTIFICATION_MSM_ENUM.signal_quality_change: c_ulong,
    WLAN_NOTIFICATION_MSM_ENUM.disassociating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.disconnected: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.peer_join: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.peer_leave: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.adapter_removal: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.adapter_operation_mode_change: c_ulong,
}

WLANNotificationSourceDict = {
    WLAN_NOTIFICATION_SOURCE_NONE: "WLAN_NOTIFICATION_SOURCE_NONE",
    WLAN_NOTIFICATION_SOURCE_ONEX: "WLAN_NOTIFICATION_SOURCE_ONEX",
    WLAN_NOTIFICATION_SOURCE_ACM: "WLAN_NOTIFICATION_SOURCE_ACM",
    WLAN_NOTIFICATION_SOURCE_MSM: "WLAN_NOTIFICATION_SOURCE_MSM",
    WLAN_NOTIFICATION_SOURCE_SECURITY: "WLAN_NOTIFICATION_SOURCE_SECURITY",
    WLAN_NOTIFICATION_SOURCE_IHV: "WLAN_NOTIFICATION_SOURCE_IHV",
    WLAN_NOTIFICATION_SOURCE_ALL: "WLAN_NOTIFICATION_SOURCE_ALL",
}


class WLANNotificationACM(Enum):
    start = 0
    autoconf_enabled = 1
    autoconf_disabled = 2
    background_scan_enabled = 3
    background_scan_disabled = 4
    bss_type_change = 5
    power_setting_change = 6
    scan_complete = 7
    scan_fail = 8
    connection_start = 9
    connection_complete = 10
    connection_attempt_fail = 11
    filter_list_change = 12
    interface_arrival = 13
    interface_removal = 14
    profile_change = 15
    profile_name_change = 16
    profiles_exhausted = 17
    network_not_available = 18
    network_available = 19
    disconnecting = 20
    disconnected = 21
    adhoc_network_state_change = 22
    profile_unblocked = 23
    screen_power_change = 24
    profile_blocked = 25
    scan_list_refresh = 26
    operational_state_change = 27
    end = 28


class Error(Exception):
    pass


class WirelessNetworkBSSWLANOpenHandleError(Exception):
    """Exception raised for errors in the input."""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class WLANScanError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class WLANGetNetworkBSSListError(Error):
    """Exception raised for errors getting the BSS list

    Attributes:
        expression -- input expression in which the error occured
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class WirelessNetwork(object):
    def __init__(self, wireless_network):
        self.ssid = wireless_network.dot11Ssid.SSID[:DOT11_SSID_MAX_LENGTH]
        self.profile_name = wireless_network.ProfileName
        self.bss_type = DOT11_BSS_TYPE_DICT.get(wireless_network.dot11BssType, 0)
        self.number_of_bssids = wireless_network.NumberOfBssids
        self.connectable = bool(wireless_network.NetworkConnectable)
        self.number_of_phy_types = wireless_network.NumberOfPhyTypes
        self.signal_quality = wireless_network.wlanSignalQuality
        self.security_enabled = bool(wireless_network.SecurityEnabled)
        auth = wireless_network.dot11DefaultAuthAlgorithm
        self.auth = DOT11_AUTH_ALGORITHM_DICT.get(auth, 0)
        cipher = wireless_network.dot11DefaultCipherAlgorithm
        self.cipher = DOT11_CIPHER_ALGORITHM_DICT.get(cipher, 0)
        self.flags = wireless_network.Flags

    def __str__(self):
        result = ""
        if not self.profile_name:
            self.profile_name = "<No Profile>"
        result += f"Profile Name: {self.profile_name}\n"
        result += f"SSID: {self.ssid}\n"
        result += f"BSS Type: {self.bss_type}\n"
        result += f"Number of BSSIDs: {self.number_of_bssids}\n"
        result += f"Connectable: {self.connectable}\n"
        result += f"Number of PHY types: {self.number_of_phy_types}\n"
        result += f"Signal Quality: {self.signal_quality}%\n"
        result += f"Security: {self.security_enabled}\n"
        result += f"Auth: {self.auth}\n"
        result += f"Cipher: {self.cipher}\n"
        result += f"Flags: {self.flags}\n"
        return result


def zzWlanGetAvailableNetworkList(clientHandle, interfaceGuid):
    """The WlanGetAvailableNetworkList function retrieves the list of available networks on a wireless LAN interface.

    DWORD WlanGetAvailableNetworkList(
      HANDLE                       hClientHandle,
      const GUID                   *pInterfaceGuid,
      DWORD                        dwFlags,
      PVOID                        pReserved,
      PWLAN_AVAILABLE_NETWORK_LIST *ppAvailableNetworkList
    );
    """


class WLAN:
    global WLANNotificationSource

    def __init__(self) -> None:
        pass

    @staticmethod
    def get_connected_rssi(interface):
        """Returns the RSSI of the current connection"""
        query_result = WLAN.query_interface(interface, "rssi")

        return query_result

    @staticmethod
    def get_connected_bssid(interface):
        """Returns the BSSID of the current connection"""
        query_result = WLAN.query_interface(interface, "current_connection")

        if (
            interface.state
            is list(WLAN_INTERFACE_STATE_DICT.keys())[
                list(WLAN_INTERFACE_STATE_DICT.values()).index("connected")
            ]
        ):
            return query_result[1]["wlanAssociationAttributes"]["dot11Bssid"]
        else:
            return None

    @staticmethod
    def open_handle() -> HANDLE:
        """The WlanOpenHandle function opens a connection to the server.
        DWORD WlanOpenHandle(
          DWORD   dwClientVersion, # 1 for XP 2 for Vista/Server 2008
          PVOID   pReserved, # Reserved for future use. Must be set to NULL.
          PDWORD  pdwNegotiatedVersion, # Version of WLAN API used in session
          PHANDLE phClientHandle # Handle for client used by other func throughout sesion
        );
        """
        func = WLAN_API.WlanOpenHandle
        func.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)]
        func.restype = DWORD

        client_ver = (
            2  # Client version for Windows Vista and Windows Server 2008 and above.
        )
        negotiated_version = DWORD()
        client_handle = HANDLE()
        result = func(client_ver, None, byref(negotiated_version), byref(client_handle))
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise Exception(
                f"wlanapi.wlan.open_handle() failed: {SystemErrorCodes(result)}:{result}"
            )
        return client_handle

    @staticmethod
    def close_handle(client_handle: HANDLE) -> int:
        func = WLAN_API.WlanCloseHandle
        func.argtypes = [HANDLE, c_void_p]
        func.restype = DWORD
        result = func(client_handle, None)
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise Exception(
                f"wlanapi.wlan.close_handle() failed: {SystemErrorCodes(result)}:{result}"
            )
        return result

    @staticmethod
    def free_memory(memory) -> None:
        func = WLAN_API.WlanFreeMemory
        func.argtypes = [c_void_p]
        func(memory)

    @staticmethod
    def enumerate_interfaces(client_handle):
        """The enumerate_interfaces function enumerates all of the wireless LAN
        interfaces currently enabled on the local computer.

        DWORD enumerate_interfaces(
          HANDLE                    hClientHandle,
          PVOID                     pReserved,
          PWLAN_INTERFACE_INFO_LIST *ppInterfaceList
        );
        """
        func_ref = WLAN_API.WlanEnumInterfaces
        func_ref.argtypes = [HANDLE, c_void_p, POINTER(POINTER(WLANInterfaceInfoList))]
        func_ref.restype = DWORD
        wlan_ifaces = pointer(WLANInterfaceInfoList())
        result = func_ref(client_handle, None, byref(wlan_ifaces))
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise Exception(
                f"wlanapi.wlan.enumerate_interfaces failed: {SystemErrorCodes(result)}:{result}"
            )
        return wlan_ifaces

    @staticmethod
    def wlan_register_notification(client_handle: HANDLE, callback):
        WLAN_NOTIFICATION_CALLBACK_M = CFUNCTYPE(
            None,  # type for return value
            POINTER(WLANNotificationData),
            c_void_p,
            use_last_error=True,
        )

        func_ref = WLAN_API.WlanRegisterNotification
        func_ref.argtypes = [
            HANDLE,
            DWORD,
            BOOL,
            WLAN_NOTIFICATION_CALLBACK_M,
            c_void_p,
            c_void_p,
            POINTER(DWORD),
        ]
        func_ref.restype = DWORD

        notification_source = 0xFFFF
        ignore_duplicate = True
        func_callback = WLAN_NOTIFICATION_CALLBACK_M(callback)
        callback_context = None
        previous_notification_source = None

        result = func_ref(
            client_handle,
            notification_source,
            ignore_duplicate,
            func_callback,
            callback_context,
            None,
            previous_notification_source,
        )

        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise Exception(
                f"wlanapi.WLAN.wlan_register_notification failed: {SystemErrorCodes(result)}:{result}"
            )
        return func_callback

    @staticmethod
    def scan(guid) -> None:
        """Tell driver to scan for Wi-Fi networks"""
        handle = WLAN.open_handle()
        result = WLAN.wlan_scan(handle, guid)
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            WLAN.close_handle(handle)
            raise Exception(f"wlan scan() failed: {SystemErrorCodes(result)}:{result}")
        WLAN.close_handle(handle)

    @staticmethod
    def wlan_scan(client_handle: HANDLE, interface_guid: GUID, ssid=None):
        func_ref = WLAN_API.WlanScan
        func_ref.argtypes = [
            HANDLE,
            POINTER(GUID),
            POINTER(DOT11SSID),
            POINTER(WLANRawData),
            c_void_p,
        ]
        func_ref.restype = DWORD
        if ssid:
            length = len(ssid)
            if length > DOT11_SSID_MAX_LENGTH:
                raise Exception("SSIDs have a maximum length of 32 characters.")
            data = ssid
            dot11_ssid = byref(DOT11SSID(length, data))
        else:
            dot11_ssid = None  # type: ignore
        result = func_ref(client_handle, byref(interface_guid), dot11_ssid, None, None)
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise WLANScanError(
                f"wlan_scan failed: {SystemErrorCodes(result)}:{result}\n{SYSTEM_ERROR_CODE_REASON.get(result, 0)}"
            )
        return result

    @staticmethod
    def get_wireless_interfaces() -> dict:
        """Returns a list of WirelessInterface objects based on the wireless
        interfaces available.
        """
        ifaces = {}
        try:
            threads = list()
            handle = WLAN.open_handle()
            wlan_interfaces = WLAN.enumerate_interfaces(handle)
            data_type = wlan_interfaces.contents.InterfaceInfo._type_
            num = wlan_interfaces.contents.NumberOfItems
            ifaces_pointer = addressof(wlan_interfaces.contents.InterfaceInfo)
            wlan_interface_info_list = (data_type * num).from_address(ifaces_pointer)

            def WirelessInterfaceThread(index, info):
                ifaces[index] = WirelessInterface(info)

            for index, info in enumerate(wlan_interface_info_list):
                t = threading.Thread(
                    target=WirelessInterfaceThread,
                    args=(
                        index,
                        info,
                    ),
                )
                t.daemon = (
                    True  # we want the thread to terminate if the main process ends
                )
                threads.append(t)
                t.start()

            for index, t in enumerate(threads):
                t.join()

            ifaces = {
                k: ifaces[k] for k in sorted(ifaces)
            }  # sort by key (index) numerically
        except Exception:
            raise
        finally:
            WLAN.free_memory(wlan_interfaces)
            WLAN.close_handle(handle)
        return ifaces

    @staticmethod
    def get_wireless_network_bss_list(interface) -> list:
        """Returns a list of WirelessNetworkBss objects based on the wireless
        networks available.
        """
        connected_bssid = None
        with contextlib.suppress(TypeError):
            connected_bssid = WLAN.get_connected_bssid(interface)

        networks = []
        handle = WLAN.open_handle()
        bss_list = None
        with contextlib.suppress(WLANGetNetworkBSSListError):
            bss_list = WLAN.get_network_bss_list(handle, interface.guid)
            data_type = bss_list.contents.wlanBssEntries._type_
            _numberOfItems = bss_list.contents.NumberOfItems
            bss_pointer = addressof(bss_list.contents.wlanBssEntries)
            bss_entries_list = (data_type * _numberOfItems).from_address(bss_pointer)

            for bss_entry in bss_entries_list:
                if connected_bssid:
                    networks.append(WirelessNetworkBss(bss_entry, connected_bssid))
                else:
                    networks.append(WirelessNetworkBss(bss_entry))

        if bss_list is not None:
            # print("if get_wireless_network_bss_list bss_list is not None")
            WLAN.free_memory(bss_list)
        if handle is not None:
            # print("if get_wireless_network_bss_list handle is not None")
            WLAN.close_handle(handle)
        return networks

    @staticmethod
    def get_network_bss_list(clientHandle, interfaceGuid, ssid=None):
        """The WlanGetNetworkBssList function retrieves a list of the basic service set
        (BSS) entries of the wireless network or networks on a given wireless LAN interface.
        DWORD WlanGetNetworkBssList(
          HANDLE            hClientHandle,
          const GUID        *pInterfaceGuid,
          const PDOT11_SSID pDot11Ssid,
          DOT11_BSS_TYPE    dot11BssType,
          BOOL              bSecurityEnabled,
          PVOID             pReserved,
          PWLAN_BSS_LIST    *ppWlanBssList
        );
        """
        func = WLAN_API.WlanGetNetworkBssList
        func.argtypes = [
            HANDLE,
            POINTER(GUID),
            POINTER(DOT11SSID),  # POINTER(DOT11SSID),
            c_void_p,  # DOT11_BSS_TYPE,
            c_void_p,  # BOOL,
            c_void_p,  # c_void_p,
            POINTER(POINTER(WLANBSSList)),
        ]
        func.restype = DWORD
        wlan_bss_list_pointer = pointer(WLANBSSList())

        if ssid:
            length = len(ssid)
            if length > DOT11_SSID_MAX_LENGTH:
                raise Exception("SSIDs have a maximum length of 32 characters.")
            dot11_ssid = byref(DOT11SSID(length, ssid))
        else:
            dot11_ssid = None

        result = func(
            clientHandle,
            byref(interfaceGuid),
            dot11_ssid,
            None,
            None,
            None,
            byref(wlan_bss_list_pointer),
        )
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise WLANGetNetworkBSSListError(
                f"wlan_get_network_bss_list failed: {SystemErrorCodes(result)}:{result}"
            )
        return wlan_bss_list_pointer

    @staticmethod
    def wlan_query_interface_wrapper(client_handle, interface_guid, op_code):
        """The WlanQueryInterface function queries various parameters of a specified interface.
        DWORD WlanQueryInterface(
          HANDLE                  hClientHandle,
          const GUID              *pInterfaceGuid,
          WLAN_INTF_OPCODE        OpCode,
          PVOID                   pReserved,
          PDWORD                  pdwDataSize,
          PVOID                   *ppData,
          PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType
        );
        """
        func = WLAN_API.WlanQueryInterface
        opcode_name = WLAN_INTF_OPCODE_DICT[op_code.value]
        return_type = WLAN_INTF_OPCODE_TYPE_DICT[opcode_name]
        # print("{} {} {}".format(op_code.value, opcode_name, return_type))
        func.argtypes = [
            HANDLE,
            POINTER(GUID),
            WLAN_INTF_OPCODE,
            c_void_p,
            POINTER(DWORD),
            POINTER(POINTER(return_type)),
            POINTER(WLAN_OPCODE_VALUE_TYPE),
        ]
        func.restype = DWORD
        pdwDataSize = DWORD()
        ppData = pointer(return_type())
        pWlanOpcodeValueType = WLAN_OPCODE_VALUE_TYPE()
        result = func(
            client_handle,
            byref(interface_guid),
            op_code,
            None,
            pdwDataSize,
            ppData,
            pWlanOpcodeValueType,
        )
        # print("{} {}".format(result, SystemErrorCodes(result)))
        # print(ppData.contents)
        if result is not SystemErrorCodes.ERROR_SUCCESS.value:
            raise WirelessNetworkBSSWLANOpenHandleError(
                f"wireless_network_bss_wlan_open_handle failed: {SystemErrorCodes(result)}:{result}"
            )
        return ppData

    @staticmethod
    def query_interface(wireless_interface, opcode_item):
        """Query interface for connection/association attributes"""
        handle = WLAN.open_handle()
        opcode_item_ext = "".join(["wlan_intf_opcode_", opcode_item])
        # print(opcode_item_ext)
        opcode = None
        for key, val in WLAN_INTF_OPCODE_DICT.items():
            if val == opcode_item_ext:
                opcode = WLAN_INTF_OPCODE(key)
                break
        # print(opcode)
        try:
            result = WLAN.wlan_query_interface_wrapper(
                handle, wireless_interface.guid, opcode
            )
            # print(result)
            result_contents = result.contents
            if opcode_item == "interface_state":
                ext_out = WLAN_INTERFACE_STATE_DICT.get(result_contents.value, 0)
            elif opcode_item == "current_connection":
                isState = WLAN_INTERFACE_STATE_DICT.get(result_contents.isState, 0)
                wlanConnectionMode = WLAN_CONNECTION_MODE_DICT.get(
                    result_contents.wlanConnectionMode, 5
                )
                strProfileName = result_contents.strProfileName
                assocAttribs = result_contents.wlanAssociationAttributes
                # WLAN_ASSOCIATION_ATTRIBUTES does not have RSSI, but "signal quality" instead.
                wlanAssociationAttributes = {
                    "dot11Ssid": assocAttribs.dot11Ssid.SSID,
                    "dot11BssType": DOT11_BSS_TYPE_DICT.get(
                        assocAttribs.dot11BssType, 0
                    ),
                    "dot11Bssid": convert_mac_address_to_string(
                        assocAttribs.dot11Bssid
                    ),
                    "dot11PhyType": DOT11_PHY_TYPE_DICT.get(
                        assocAttribs.dot11PhyType, 0
                    ),
                    "uDot11PhyIndex": c_long(assocAttribs.uDot11PhyIndex).value,
                    "wlanSignalQuality": c_long(assocAttribs.wlanSignalQuality).value,
                    "ulRxRate": c_long(assocAttribs.ulRxRate).value,
                    "ulTxRate": c_long(assocAttribs.ulTxRate).value,
                }
                secAttribs = result_contents.wlanSecurityAttributes
                wlanSecurityAttributes = {
                    "bSecurityEnabled": secAttribs.bSecurityEnabled,
                    "bOneXEnabled": secAttribs.bOneXEnabled,
                    "dot11AuthAlgorithm": DOT11_AUTH_ALGORITHM_DICT.get(
                        secAttribs.dot11AuthAlgorithm, 0
                    ),
                    "dot11CipherAlgorithm": DOT11_CIPHER_ALGORITHM_DICT.get(
                        secAttribs.dot11CipherAlgorithm, 0
                    ),
                }
                ext_out = {
                    "isState": isState,
                    "wlanConnectionMode": wlanConnectionMode,
                    "strProfileName": strProfileName,
                    "wlanAssociationAttributes": wlanAssociationAttributes,
                    "wlanSecurityAttributes": wlanSecurityAttributes,
                }
            else:
                ext_out = None
        except WirelessNetworkBSSWLANOpenHandleError as error:
            return error.message
        finally:
            WLAN.close_handle(handle)
        return result.contents, ext_out
