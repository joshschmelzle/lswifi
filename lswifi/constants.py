# -*- coding: utf-8 -*-

"""
lswifi.constants
~~~~~~~~~~~~~~~

define app constant values
"""

APNAMEACKFILE = "apnames.ack"
APNAMEJSONFILE = "apnames.json"

CIPHER_SUITE_DICT = {
    0: "Use group cipher suite",
    1: "WEP-40",  # WEP
    2: "TKIP",  # WPA-Personal (TKIP is limited to 54 Mbps)
    3: "Reserved",
    4: "AES",  # CCMP-128 WPA2-Enterprise 00-0F-AC:4 / WPA2-Personal 00-0F-AC:4
    5: "WEP-104",
    6: "BIP-CMAC-128",
    7: "Group addressed traffic not allowed",
    8: "GCMP-128",
    9: "GCMP-256",  # WPA3-Enterprise 00-0F-AC:9 / WPA3-Personal 00-0F-AC:9
    10: "CMAC-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
    14: "Reserved",
    15: "Reserved",
}

AKM_SUITE_DICT = {
    0: "Reserved",
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X",
    6: "PSK",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    10: "APPeerKey",
    11: "802.1X-Suite-B-SHA-256",
    12: "802.1X 192-bit",  # WPA3 - Enterprise
    13: "FT-802.1X-SHA-384",
    18: "OWE",
}

INTERWORKING_NETWORK_TYPE = {
    0: "Private network",
    1: "Private network with guest access",
    2: "Chargeable public network",
    3: "Free public network",
    4: "Personal device network",
    5: "Reserved",
    6: "Reserved",
    7: "Reserved",
    8: "Reserved",
    9: "Reserved",
    10: "Reserved",
    11: "Reserved",
    12: "Reserved",
    13: "Reserved",
    14: "Test or experimental",
    15: "Wildcard",
}

IE_DICT = {
    0: "SSID parameter",
    1: "Supported Rates",
    3: "DSSS Parameter Set",
    5: "Traffic Indication Map",
    7: "Country",  # 802.11d
    11: "BSS Load",  # 802.11e
    32: "Power Constraint",  # 802.11h
    33: "Power Capability",
    34: "TPC Request",
    35: "TPC Report",  # 802.11h
    36: "Supported Channels",
    37: "Channel Switch Announcement",
    38: "Measurement Request",
    39: "Measurement Report",
    40: "Quiet Element",  # 802.11h
    41: "IBSS DFS",
    42: "ERP",
    45: "HT Capabilities",
    # 47: "ERP Information",
    48: "RSN Information",
    50: "Extended Supported Rates",
    51: "AP Channel Report",
    54: "Mobility Domain",
    61: "HT Operation",
    67: "BSS Available Admission Capacity",
    69: "Time Advertisement",
    70: "RM Enabled Capabilities",  # 802.11r
    71: "Multiple BSSID",
    74: "Overlapping BSS Scan Parameters",
    107: "Interworking",
    108: "Advertisement Protocol",
    113: "Mesh Configuration",  # 802.11s
    127: "Extended Capabilities",
    133: "Cisco CCX1 CKIP + Device Name",
    149: "Cisco Unknown 95",
    150: "Cisco Vendor Specific",
    173: "Symbol Proprietary",
    191: "VHT Capabilities",
    192: "VHT Operation",
    195: "VHT Tx Power Envelope",
    221: "Vendor Specific",
    255: "Extension",
}

VENDOR_SPECIFIC_DICT = {
    "00-0B-86": ["Aruba", "Aruba Networks Inc."],
    "00-50-F2": ["Microsoft", "Microsoft Corporation"],
    "00-03-7F": ["Atheros", "Atheros Communications Inc."],
    "00-10-18": ["Broadcom", "Broadcom"],
    "00-17-F2": ["Apple", "Apple Inc."],
    "00-15-6D": ["Ubiquiti", "Ubiquiti Networks Inc."],
    "00-26-86": ["Quantenna", "Quantenna"],
}

EXTENSION_IE_DICT = {
    35: "HE Capabilities",
    36: "HE Operation",
    37: "UORA Parameter Set",
    38: "MU EDCA Parameter Set",
    39: "Spatial Reuse Parameter",
    41: "NDP Feedback Report",
    42: "BSS Color Change Announcement",
    43: "Quiet Time Period Setup",
    45: "ESS Report",
    46: "OPS",
    47: "HE BSS Load",
}


_40MHZ_CHANNEL_LIST = {
    "13-": ["13", "(9)"],
    "9+": ["9", "(13)"],
    "12-": ["12", "(8)"],
    "8+": ["8", "(12)"],
    "11-": ["11", "(7)"],
    "7+": ["7", "(11)"],
    "10-": ["10", "(6)"],
    "6+": ["6", "(10)"],
    "9-": ["9", "(5)"],
    "5+": ["5", "(9)"],
    "8-": ["8", "(4)"],
    "4+": ["4", "(8)"],
    "7-": ["7", "(3)"],
    "3+": ["3", "(7)"],
    "6-": ["6", "(2)"],
    "2+": ["2", "(6)"],
    "5-": ["5", "(1)"],
    "1+": ["1", "(5)"],
    "32+": ["32", "(36)"],
    "36-": ["36", "(32)"],
    "36+": ["36", "(40)"],
    "40-": ["40", "(36)"],
    "44+": ["44", "(48)"],
    "48-": ["48", "(44)"],
    "52+": ["52", "(56)"],
    "56-": ["56", "(52)"],
    "60+": ["60", "(64)"],
    "64-": ["64", "(60)"],
    "100+": ["100", "(104)"],
    "104-": ["104", "(100)"],
    "108+": ["108", "(112)"],
    "112-": ["112", "(108)"],
    "116+": ["116", "(120)"],
    "120-": ["120", "(116)"],
    "124+": ["124", "(128)"],
    "128-": ["128", "(124)"],
    "132+": ["132", "(136)"],
    "136-": ["136", "(132)"],
    "140+": ["140", "(144)"],
    "144-": ["144", "(140)"],
    "149+": ["149", "(153)"],
    "153-": ["153", "(149)"],
    "157+": ["157", "(161)"],
    "161-": ["161", "(157)"],
}

_80MHZ_CHANNEL_LIST = {
    "42": ["36", "40", "44", "48"],
    "58": ["52", "56", "60", "64"],
    "106": ["100", "104", "108", "112"],
    "122": ["116", "120", "124", "128"],
    "138": ["132", "136", "140", "144"],
    "155": ["149", "153", "157", "161"],
}

_160MHZ_CHANNEL_LIST = {
    "50": ["36", "40", "44", "48", "52", "56", "60", "64"],
    "114": ["100", "104", "108", "112", "116", "120", "124", "128"],
}

_20MHZ_CHANNEL_LIST = {
    "2412": "1",
    "2417": "2",
    "2422": "3",
    "2427": "4",
    "2432": "5",
    "2437": "6",
    "2442": "7",
    "2447": "8",
    "2452": "9",
    "2457": "10",
    "2462": "11",
    "2467": "12",
    "2472": "13",
    "2484": "14",
    "5160": "32",
    "5170": "34",
    "5180": "36",
    "5190": "38",
    "5200": "40",
    "5210": "42",
    "5220": "44",
    "5230": "46",
    "5240": "48",
    "5250": "50",
    "5260": "52",
    "5270": "54",
    "5280": "56",
    "5290": "58",
    "5300": "60",
    "5310": "62",
    "5320": "64",
    "5340": "68",
    "5480": "96",
    "5500": "100",
    "5510": "102",
    "5520": "104",
    "5530": "106",
    "5540": "108",
    "5550": "110",
    "5560": "112",
    "5570": "114",
    "5580": "116",
    "5590": "118",
    "5600": "120",
    "5610": "122",
    "5620": "124",
    "5630": "126",
    "5640": "128",
    "5660": "132",
    "5670": "134",
    "5680": "136",
    "5700": "140",
    "5710": "142",
    "5720": "144",
    "5745": "149",
    "5755": "151",
    "5765": "153",
    "5775": "155",
    "5785": "157",
    "5795": "159",
    "5805": "161",
    "5825": "165",
    "5845": "169",
    "5865": "173",
    "4915": "183",
    "4920": "184",
    "4925": "185",
    "4935": "187",
    "4940": "188",
    "4945": "189",
    "4960": "192",
    "4980": "196",
}
