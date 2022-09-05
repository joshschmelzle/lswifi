# -*- coding: utf-8 -*-

"""
lswifi.libpcap
~~~~~~~~~~~~~~

define libpcap class to help export scan results to pcap file.

https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat

perhaps in future pcapng. 

inspiration and code extracted from https://github.com/secdev/scapy/blob/master/scapy/libs/winpcapy.py
"""

# stdlib imports
import logging
import struct
import time
from ctypes import *

""" FORMAT CHARACTERS FOR STRUCT
================================

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

# misc
u_short = c_ushort
bpf_int32 = c_int
u_int = c_int
bpf_u_int32 = u_int
pcap = c_void_p
pcap_dumper = c_void_p
u_char = c_ubyte
FILE = c_void_p
STRING = c_char_p


class timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


""" GLOBAL HEADER
=================
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
"""


class pcap_global_header(Structure):
    _fields_ = [
        ("magic_number", bpf_u_int32),
        ("version_major", u_short),
        ("version_minor", u_short),
        ("thiszone", bpf_int32),
        ("sigfigs", bpf_u_int32),
        ("snaplen", bpf_u_int32),
        ("linktype", bpf_u_int32),
    ]


""" RECORD (PACKET) HEADER
==========================
Each captured packet starts with (any byte alignment possible):

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
"""


class pcap_packet_header(Structure):
    """
    Header of a packet in the pcap file.
    """

    _fields_ = [("ts", timeval), ("caplen", bpf_u_int32), ("len", bpf_u_int32)]


LIBPCAP_GLOBAL_HEADER_FMT = "@ I H H i I I I "

"""
Magic Number (32 bits):  an unsigned magic number, whose value is
    either the hexadecimal number 0xA1B2C3D4 or the hexadecimal number
    0xA1B23C4D.

    If the value is 0xA1B2C3D4, time stamps in Packet Records (see
    Figure 2) are in seconds and microseconds; if it is 0xA1B23C4D,
    time stamps in Packet Records are in seconds and nanoseconds.

Used to detect the file format itself and the byte ordering. 

    The writing application writes 0xa1b2c3d4 with it's native byte 
    ordering format into this field. 

    The reading application will read either 0xa1b2c3d4 (identical)
    or 0xd4c3b2a1 (swapped).

    If the reading application reads the swapped 0xd4c3b2a1 value, 
    it knows that all the following fields will have to be swapped too.
"""

LIBPCAP_MAGIC_NUMBER = 2712847316  # hex 0xA1B2C3D4

LIBPCAP_VERSION_MAJOR = 2
LIBPCAP_VERSION_MINOR = 4

"""
If the timestamps are in GMT (UTC), thiszone is simply 0.
time stamps should always be GMT. so, this is 0.
"""
LIBPCAP_THISZONE = 0

"""
sigfigs: in theory, the accuracy of time stamps in the capture;
in practice, all tools set it to 0
"""
LIBPCAP_SIGFIGS = 0
LIBPCAP_SNAPLEN = 65535


class LINKTYPE(object):
    """
    LINK-LAYER HEADER TYPE VALUES
    https://www.tcpdump.org/linktypes.html
    """

    def __init__(self, name, value, dlt):
        self.name = name
        self.value = value
        self.dlt = dlt


LINKTYPE_IEEE802_11 = LINKTYPE("LINKTYPE_IEEE802_11", 105, "DLT_IEEE802_11")
LINKTYPE_IEEE802_11_RADIOTAP = LINKTYPE(
    "LINKTYPE_IEEE802_11_RADIOTAP", 127, "DLT_IEEE802_11_RADIO"
)

LIBPCAP_RECORD_HEADER_FMT = "@ I I I I"

# LINK-LAYER HEADER TYPE VALUES:
# LINKTYPE_ETHERNET             , 1  , IEEE 802.3 Ethernet
# LINKTYPE_IEEE802_11           , 105, IEEE 802.11
# LINKTYPE_IEEE802_11_RADIOTAP  , 127, Radiotap link-layer information followed by an 802.11 header


""" PACKET DATA
The actual packet data will immediately follow the packet header as a data blob of incl_len bytes without a specific byte alignment.
"""


class LIBPCAP:
    def __init__(self, file, header_type, data):
        self.log = logging.getLogger(__name__)
        self.file = file
        self.header_type = header_type
        self.data = data
        self.pcap = None

    def write(self):
        self.pcap = open(self.file, "wb")
        self.writerheader()
        self.writerdata()

    def write_global_header(self):
        self.pcap.write(
            struct.pack(
                LIBPCAP_GLOBAL_HEADER_FMT,
                LIBPCAP_MAGIC_NUMBER,
                LIBPCAP_VERSION_MAJOR,
                LIBPCAP_VERSION_MINOR,
                LIBPCAP_THISZONE,
                LIBPCAP_SIGFIGS,
                LIBPCAP_SNAPLEN,
                self.header_type,
            )
        )
        self.log.debug(f"[+] Header Type: {header_type}")

    def write_record_header(self):
        """
        Each captured packet starts with (any byte alignment possible):
        """
        self.pcap.write(
            struct.pack(
                self.header_type,
                int(time.time()),
                int(time.time() * 1000000),
                len(self.data),
                len(self.data),
            )
        )
        self.log.debug(f"[+] Record Header: {self.data}")

    def write_packet_data(self):
        """
        The actual packet data will immediately follow the packet header
        as a data blob of incl_len bytes without a specific byte alignment.
        """
        self.pcap.write(self.data)
        self.log.debug(f"[+] Packet Data: {self.data}")

    def writelist(self, data=[]):
        for i in data:
            self.write(i)
        return

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
