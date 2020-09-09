# -*- coding: utf-8 -*-

"""
lswifi.libpcap
~~~~~~~~~~~~~~~

define libpcap class to help export to pcap
"""


# python imports
import struct
import time
import logging

# app imports

""" global header
This header starts the libpcap file and will be followed by the first packet header:

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

struct format characters

| format | C Type             | Python type | standard size |
| ------ | ------------------ | ----------- | ------------- |
| H      | unsigned short     | integer     | 2             |
| I      | unsigned int       | integer     | 4             |
| i      | int                | integer     | 4             |
| B      | u_int8_t           | integer     | 1             |
| b      | signed char        | integer     | 1             |

byte order, size, and alignment

| character | byte order    | size     | alignment |
| --------- | ------------- | -------- | --------- |
| @         | native        | native   | native    |
| =         | native        | standard | none      |
| <         | little-endian | standard | none      |
| >         | big-endian    | standard | none      |
| !         | network       | standard | none      |

"""

LIBPCAP_GLOBAL_HEADER_FMT = "@ I H H i I I I "

LIBPCAP_MAGIC_NUMBER = 2712847316  # hex 0xA1B2C3D4
LIBPCAP_VERSION_MAJOR = 2
LIBPCAP_VERSION_MINOR = 4
LIBPCAP_THISZONE = 0
LIBPCAP_SIGFIGS = 0
LIBPCAP_SNAPLEN = 65535
LIBPCAP_LINK_LAYER_HEADER_TYPE = 127

LIBPCAP_RECORD_HEADER_FMT = "@ I I I I"

# LINK-LAYER HEADER TYPE VALUES:
# LINKTYPE_ETHERNET             , 1  , IEEE 802.3 Ethernet
# LINKTYPE_IEEE802_11           , 105, IEEE 802.11
# LINKTYPE_IEEE802_11_RADIOTAP  , 127, Radiotap link-layer information followed by an 802.11 header

""" Record (Packet) Header
Each captured packet starts with (any byte alignment possible):

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
"""


class LIBPCAP:
    def __init__(self, file, header_type=LIBPCAP_LINK_LAYER_HEADER_TYPE):
        log = logging.getLogger(__name__)
        self.pcap = open(file, "wb")
        self.pcap.write(
            struct.pack(
                LIBPCAP_GLOBAL_HEADER_FMT,
                LIBPCAP_MAGIC_NUMBER,
                LIBPCAP_VERSION_MAJOR,
                LIBPCAP_VERSION_MINOR,
                LIBPCAP_THISZONE,
                LIBPCAP_SIGFIGS,
                LIBPCAP_SNAPLEN,
                header_type,
            )
        )
        log.debug(f"[+] Header Type: {header_type}")

    def writelist(self, data=[]):
        for i in data:
            self.write(i)
        return

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split("."))
        length = len(data)
        self.pcap.write(
            struct.pack(LIBPCAP_RECORD_HEADER_FMT, ts_sec, ts_usec, length, length)
        )
        self.pcap.write(data)

    def close(self):
        self.pcap.close()


""" radiotap header
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));
"""

RADIOTAP_HEADER_FMT = "@ B B H I"

RADIOTAP_VERSION = 0
RADIOTAP_PAD = 0
RADIOTAP_LEN = 0
RADIOTAP_FIELDS_PRESENT = 0x0000  # fields are strictly ordered, must appear in the header in order they are specified here
# Channel           (bit 3 (pos 4)) u16 freq, u16 flags, format I
# Antenna signal    (bit 5 (pos 6)) 8-bit signed, format b
# OFDM
# 2 GHz spectrum
# 5 GHz spectrum


def set_bit(value, bit):
    return value | (1 << bit)


RADIOTAP_FIELDS_PRESENT = set_bit(RADIOTAP_FIELDS_PRESENT, 3)
RADIOTAP_FIELDS_PRESENT = set_bit(RADIOTAP_FIELDS_PRESENT, 5)
RADIOTAP_HEADER_FMT = RADIOTAP_HEADER_FMT + "I b"


class RADIOTAP:
    def __init__(self, channel, rssi):
        return struct.pack(RADIO)


""" IEEE header
TODO: fill in. 
"""


class IEEE80211:
    pass
