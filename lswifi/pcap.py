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
lswifi.pcap
~~~~~~~~~~~

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

PCAP_MAGIC = 0xA1B2C3D4


def parse_radiotap_header(packet_data: bytes) -> dict:
    """
    Parse radiotap header and return extracted fields.

    Handles extended present flags, field alignment, and vendor namespaces.
    """
    result = {
        "rssi": -99,
        "noise": None,
        "frequency": 0,
        "channel": 0,
        "flags": 0,
        "rate": 0,
        "antenna": 0,
        "fcs_present": False,
        "header_len": 0,
    }

    if len(packet_data) < 8:
        return result

    version, pad, header_len = struct.unpack_from("<BBH", packet_data, 0)
    result["header_len"] = header_len

    if header_len > len(packet_data) or header_len < 8:
        return result

    present_flags = []
    offset = 4
    while offset + 4 <= header_len:
        present = struct.unpack_from("<I", packet_data, offset)[0]
        present_flags.append(present)
        offset += 4
        if not (present & 0x80000000):  # Extension bit (bit 31)
            break

    if not present_flags:
        return result

    first_present = present_flags[0]
    data_offset = 4 + (len(present_flags) * 4)

    def align_to(off: int, alignment: int) -> int:
        remainder = off % alignment
        return off + (alignment - remainder) if remainder else off

    # TSFT (8 bytes, 8-byte aligned)
    if first_present & RT_PRESENT_TSFT:
        data_offset = align_to(data_offset, 8)
        data_offset += 8

    # Flags (1 byte)
    if first_present & RT_PRESENT_FLAGS:
        if data_offset < header_len:
            result["flags"] = packet_data[data_offset]
            result["fcs_present"] = bool(result["flags"] & 0x10)
        data_offset += 1

    # Rate (1 byte)
    if first_present & RT_PRESENT_RATE:
        if data_offset < header_len:
            result["rate"] = packet_data[data_offset] * 0.5
        data_offset += 1

    # Channel (4 bytes: 2 freq + 2 flags, 2-byte aligned)
    if first_present & RT_PRESENT_CHANNEL:
        data_offset = align_to(data_offset, 2)
        if data_offset + 4 <= header_len:
            freq, chan_flags = struct.unpack_from("<HH", packet_data, data_offset)
            result["frequency"] = freq
            result["channel"] = frequency_to_channel(freq)
        data_offset += 4

    # FHSS (2 bytes)
    if first_present & RT_PRESENT_FHSS:
        data_offset += 2

    # Antenna Signal dBm (1 byte, signed)
    if first_present & RT_PRESENT_DBM_ANTSIGNAL:
        if data_offset < header_len:
            result["rssi"] = struct.unpack_from("b", packet_data, data_offset)[0]
        data_offset += 1

    # Antenna Noise dBm (1 byte, signed)
    if first_present & 0x00000040:  # RT_PRESENT_DBM_ANTNOISE
        if data_offset < header_len:
            result["noise"] = struct.unpack_from("b", packet_data, data_offset)[0]
        data_offset += 1

    # Lock Quality (2 bytes, 2-byte aligned)
    if first_present & 0x00000080:
        data_offset = align_to(data_offset, 2)
        data_offset += 2

    # TX Attenuation (2 bytes, 2-byte aligned)
    if first_present & 0x00000100:
        data_offset = align_to(data_offset, 2)
        data_offset += 2

    # dB TX Attenuation (2 bytes, 2-byte aligned)
    if first_present & 0x00000200:
        data_offset = align_to(data_offset, 2)
        data_offset += 2

    # dBm TX Power (1 byte)
    if first_present & 0x00000400:
        data_offset += 1

    # Antenna (1 byte)
    if first_present & 0x00000800:
        if data_offset < header_len:
            result["antenna"] = packet_data[data_offset]
        data_offset += 1

    return result


def frequency_to_channel(freq: int) -> int:
    """Convert frequency in MHz to channel number."""
    # 2.4 GHz
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5

    # 5 GHz
    if 5170 <= freq <= 5885:
        return (freq - 5000) // 5

    # 6 GHz
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5

    return 0


class PCAP:
    """Reader/writer for pcap and pcapng capture files."""

    def __init__(self, file_path, mode="w"):
        self.log = logging.getLogger(__name__)
        self.file_path = file_path
        self.mode = mode
        self.file = None
        self.interfaces = []
        self.interface_map = {}

    def open(self):
        self.file = open(self.file_path, self.mode + "b")  # noqa: SIM115
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

    def _detect_format(self):
        """Detect if file is pcap or pcapng format. Returns 'pcap', 'pcapng', or None."""
        pos = self.file.tell()
        magic = self.file.read(4)
        self.file.seek(pos)

        if len(magic) < 4:
            return None

        magic_val = struct.unpack("<I", magic)[0]

        if magic_val == PCAPNG_BLOCK_TYPE_SHB:
            return "pcapng"

        # legacy pcap
        if magic_val == PCAP_MAGIC:
            return "pcap"

        return None

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
        # Timestamps are in units of 10^-6 seconds (microseconds)
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
        if freq >= 5950 or freq >= 5150:
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

        file_format = self._detect_format()

        if file_format == "pcap":
            self.log.debug("Detected legacy pcap format")
            yield from self._read_pcap_packets()
            return
        elif file_format == "pcapng":
            self.log.debug("Detected pcapng format")
        else:
            self.log.error("Unknown file format")
            return

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

                interface_id, ts_high, ts_low, caplen, origlen = struct.unpack(
                    "<IIIII", data[:20]
                )

                ts_microseconds = (ts_high << 32) | ts_low
                timestamp = ts_microseconds / 1_000_000.0

                packet_data = data[20 : 20 + caplen]

                if interface_id < len(interfaces):
                    linktype, interface_name = interfaces[interface_id]

                    yield (interface_id, interface_name, timestamp, packet_data)

    def _read_pcap_packets(self):
        """Generator to read packets from legacy pcap format."""
        header = self.file.read(24)
        if len(header) < 24:
            self.log.error("Invalid pcap file: header too short")
            return

        magic = struct.unpack("<I", header[:4])[0]

        if magic != PCAP_MAGIC:
            self.log.error(f"Unknown pcap magic: {hex(magic)}")
            return

        version_major, version_minor, _, _, snaplen, linktype = struct.unpack(
            "<HHIIII", header[4:24]
        )

        self.log.debug(
            f"PCAP: version={version_major}.{version_minor}, "
            f"linktype={linktype}, snaplen={snaplen}"
        )

        if linktype not in (LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP):
            self.log.warning(f"Unexpected linktype {linktype}, may not be 802.11 data")

        interface_name = "pcap0"
        packet_num = 0

        while True:
            pkt_header = self.file.read(16)
            if len(pkt_header) < 16:
                break

            ts_sec, ts_usec, caplen, origlen = struct.unpack("<IIII", pkt_header)

            timestamp = ts_sec + (ts_usec / 1_000_000.0)

            packet_data = self.file.read(caplen)
            if len(packet_data) < caplen:
                self.log.warning(f"Truncated packet {packet_num}")
                break

            packet_num += 1
            yield (0, interface_name, timestamp, packet_data)
