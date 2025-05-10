# -*- coding: utf-8 -*-
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
lswifi.pcapng
~~~~~~~~~~~~~

"""

import logging
import platform
import struct
import sys

from lswifi.__version__ import __title__, __version__

PCAPNG_BLOCK_TYPE_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_TYPE_IDB = 0x00000001
PCAPNG_BLOCK_TYPE_EPB = 0x00000006

PCAPNG_OPT_END = 0
PCAPNG_OPT_COMMENT = 1
PCAPNG_OPT_IDB_NAME = 2
PCAPNG_OPT_IDB_DESCRIPTION = 3
PCAPNG_OPT_SHB_USERAPPL = 4
PCAPNG_OPT_SHB_HARDWARE = 2
PCAPNG_OPT_SHB_OS = 3
PCAPNG_OPT_IDB_IF_TSRESOL = 9

LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

RADIOTAP_HEADER_FMT = "< B B H I"

RT_PRESENT_TSFT = 0x00000001
RT_PRESENT_FLAGS = 0x00000002
RT_PRESENT_RATE = 0x00000004
RT_PRESENT_CHANNEL = 0x00000008
RT_PRESENT_FHSS = 0x00000010
RT_PRESENT_DBM_ANTSIGNAL = 0x00000020


class PCAPNG:
    def __init__(self, file_path, mode="w"):
        self.log = logging.getLogger(__name__)
        self.file_path = file_path
        self.mode = mode
        self.file = None
        self.interfaces = []
        self.interface_map = {}

    def open(self):
        self.file = open(self.file_path, self.mode + "b")
        if self.mode == "w":
            self.write_section_header()
        return self

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _write_block(self, block_type, block_data):
        length = len(block_data) + 12
        padding_len = (4 - (length % 4)) % 4
        padding = b"\x00" * padding_len

        block_type_bytes = struct.pack("<I", block_type)
        block_len_bytes = struct.pack("<I", length + padding_len)

        self.log.debug(
            f"Writing block: type={hex(block_type)}, length={length + padding_len}"
        )
        self.log.debug(f"Block type bytes: {block_type_bytes.hex()}")
        self.log.debug(f"Block length bytes: {block_len_bytes.hex()}")

        self.file.write(block_type_bytes)
        self.file.write(block_len_bytes)
        self.file.write(block_data)
        self.file.write(padding)
        self.file.write(block_len_bytes)
        # self.file.write(struct.pack("<I", block_type))
        # self.file.write(struct.pack("<I", length + padding_len))
        # self.file.write(block_data)
        # self.file.write(padding)
        # self.file.write(struct.pack("<I", length + padding_len))

    def _write_option(self, option_code, option_data=b""):
        """Write a pcapng option with proper padding"""
        if isinstance(option_data, str):
            option_data = option_data.encode()

        data_len = len(option_data)
        padding_len = (4 - (data_len % 4)) % 4
        padding = b"\x00" * padding_len

        option_code = option_code & 0xFFFF

        option = struct.pack("<HH", option_code, data_len)
        option += option_data
        option += padding

        return option

    def write_section_header(self):
        """Write the Section Header Block (SHB)"""
        # Standard magic, version 1.0, unknown section length
        magic = 0x1A2B3C4D
        version_major = 1
        version_minor = 0
        section_length = -1

        block_body = struct.pack("<IHH", magic, version_major, version_minor)
        block_body += struct.pack("<q", section_length)

        hardware_info = platform.processor() or "Unknown"
        block_body += self._write_option(PCAPNG_OPT_SHB_HARDWARE, hardware_info)

        os_info = platform.platform() or "Unknown"
        block_body += self._write_option(PCAPNG_OPT_SHB_OS, os_info)

        app_info = f"{__title__} {__version__} (py{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro})"
        block_body += self._write_option(PCAPNG_OPT_SHB_USERAPPL, app_info)

        block_body += self._write_option(
            PCAPNG_OPT_COMMENT,
            "Not a monitor mode packet capture. More details at https://github.com/joshschmelzle/lswifi",
        )

        block_body += self._write_option(PCAPNG_OPT_END)

        self.log.debug(f"SHB header hexdump:\n{self._hex_dump(block_body[:16])}")

        self._write_block(PCAPNG_BLOCK_TYPE_SHB, block_body)

    def _hex_dump(self, data, prefix=""):
        """Print a hexdump of binary data for debugging"""
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            result.append(f"{prefix}{i:04x}: {hex_str:<48} {ascii_str}")
        return "\n".join(result)

    def add_interface(
        self, name, description=None, linktype=LINKTYPE_IEEE802_11_RADIOTAP
    ):
        """Add an interface and write Interface Description Block (IDB)"""
        iface_data = struct.pack("<HHI", linktype, 0, 65535)

        if name:
            iface_data += self._write_option(PCAPNG_OPT_IDB_NAME, name.encode())

        if description:
            iface_data += self._write_option(
                PCAPNG_OPT_IDB_DESCRIPTION, description.encode()
            )

        # Set timestamp resolution to microseconds (value 6)
        # TImestamps are in units of 10^-6 seconds (microseconds)
        iface_data += self._write_option(PCAPNG_OPT_IDB_IF_TSRESOL, bytes([6]))

        iface_data += self._write_option(PCAPNG_OPT_END)
        self._write_block(PCAPNG_BLOCK_TYPE_IDB, iface_data)
        interface_id = len(self.interfaces)
        self.interfaces.append(name)
        self.interface_map[name] = interface_id
        return interface_id

    def write_packet(self, interface_id, timestamp, packet_data):
        """Write an Enhanced Packet Block (EPB)"""
        if interface_id >= len(self.interfaces):
            self.log.error(f"Invalid interface ID: {interface_id}")
            return

        ts_microseconds = int(timestamp * 1000000)
        ts_high = (ts_microseconds >> 32) & 0xFFFFFFFF
        ts_low = ts_microseconds & 0xFFFFFFFF

        packet_block = b""
        packet_block += struct.pack("<I", interface_id)
        packet_block += struct.pack("<I", ts_high)
        packet_block += struct.pack("<I", ts_low)
        packet_block += struct.pack("<I", len(packet_data))
        packet_block += struct.pack("<I", len(packet_data))
        packet_block += packet_data
        packet_block += struct.pack("<HH", 0, 0)

        self._write_block(PCAPNG_BLOCK_TYPE_EPB, packet_block)

    def create_radiotap_frame(self, bss):
        """Create a radiotap header + 802.11 frame from a WirelessNetworkBss object"""
        present_flags = (
            RT_PRESENT_FLAGS
            | RT_PRESENT_RATE
            | RT_PRESENT_CHANNEL
            | RT_PRESENT_DBM_ANTSIGNAL
        )

        header = struct.pack(RADIOTAP_HEADER_FMT, 0, 0, 24, present_flags)

        header += struct.pack("B", 0)

        # Note: In radiotap, rate is specified in 0.5 Mbps units, so 6 Mbps = 12 units = 0x0C
        header += struct.pack("B", 0x0C)

        freq = int(float(bss.channel_frequency.value) * 1000)
        if freq >= 5950:
            channel_flags = 0x0140
        elif freq >= 5150:
            channel_flags = 0x0140
        elif freq >= 2401:
            channel_flags = 0x00B0
        else:
            channel_flags = 0x0000

        header += struct.pack("<HH", freq, channel_flags)

        header += struct.pack("b", bss.rssi.value)

        header += b"\x00" * 9

        try:
            bssid_str = str(bss.bssid.value)
            bssid_clean = (
                bssid_str.replace(":", "")
                .replace("-", "")
                .replace(".", "")
                .replace("(*)", "")
            )
            if len(bssid_clean) != 12:
                self.log.error(f"Invalid BSSID format: {bssid_str}")
                bssid_bytes = b"\xff\xff\xff\xff\xff\xff"
            else:
                bssid_bytes = bytes.fromhex(bssid_clean)
        except Exception as e:
            self.log.error(f"Error parsing BSSID {bss.bssid.value}: {str(e)}")
            bssid_bytes = b"\xff\xff\xff\xff\xff\xff"

        # Type: Management (0), Subtype: Beacon (8)
        frame_control = 0x0080
        duration = 0
        dest_addr = b"\xff\xff\xff\xff\xff\xff"
        src_addr = bssid_bytes
        bssid = bssid_bytes
        seq_ctrl = 0

        mac_header = struct.pack(
            "<HH6s6s6sH", frame_control, duration, dest_addr, src_addr, bssid, seq_ctrl
        )

        timestamp = bss.timestamp
        beacon_period = bss.beacon_period

        capabilities = 0x0011
        try:
            capabilities = bss.capabilities.value
        except (AttributeError, TypeError) as e:
            self.log.error(f"Error accessing capabilities value: {str(e)}")

        fixed_params = struct.pack("<QHH", timestamp, beacon_period, capabilities)

        ie_data = bytes(bss.iesbytes)

        frame_data = mac_header + fixed_params + ie_data

        return header + frame_data

    def read_blocks(self):
        """Generator to read blocks from a pcapng file"""
        if not self.file or self.mode != "r":
            raise ValueError("File not open for reading")

        while True:
            block_type_data = self.file.read(4)
            if len(block_type_data) < 4:
                break

            block_type = struct.unpack("<I", block_type_data)[0]

            length_data = self.file.read(4)
            if len(length_data) < 4:
                break

            block_length = struct.unpack("<I", length_data)[0]

            data_length = block_length - 12

            data = self.file.read(data_length)

            self.file.read(4)

            yield (block_type, data)

    def get_packets(self):
        """Generator to extract packets from the file"""
        if not self.file or self.mode != "r":
            raise ValueError("File not open for reading")

        interfaces = []

        for block_type, data in self.read_blocks():
            if block_type == PCAPNG_BLOCK_TYPE_SHB:
                continue

            elif block_type == PCAPNG_BLOCK_TYPE_IDB:
                linktype, reserved, snaplen = struct.unpack("<HHI", data[:8])

                opt_data = data[8:]
                iface_name = None

                while len(opt_data) >= 4:
                    opt_code, opt_len = struct.unpack("<HH", opt_data[:4])
                    if opt_code == 0:
                        break

                    if opt_code == PCAPNG_OPT_IDB_NAME and opt_len > 0:
                        iface_name = (
                            opt_data[4 : 4 + opt_len]
                            .decode("utf-8", errors="ignore")
                            .strip("\x00")
                        )

                    pad_len = (4 - (opt_len % 4)) % 4
                    opt_data = opt_data[4 + opt_len + pad_len :]

                interfaces.append((linktype, iface_name))

            elif block_type == PCAPNG_BLOCK_TYPE_EPB:
                if len(data) < 20:
                    continue

                interface_id, seconds, microseconds, caplen, origlen = struct.unpack(
                    "<IIIII", data[:20]
                )

                timestamp = seconds + (microseconds / 1000000.0)

                packet_data = data[20 : 20 + caplen]

                if interface_id < len(interfaces):
                    linktype, interface_name = interfaces[interface_id]

                    yield (interface_id, interface_name, timestamp, packet_data)
