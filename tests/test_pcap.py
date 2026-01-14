# -*- encoding: utf-8

import struct
from pathlib import Path

import pytest

from lswifi.pcap import (
    PCAP,
    frequency_to_channel,
    parse_radiotap_header,
    RT_PRESENT_FLAGS,
    RT_PRESENT_RATE,
    RT_PRESENT_CHANNEL,
    RT_PRESENT_DBM_ANTSIGNAL,
    RT_PRESENT_TSFT,
)


class TestFrequencyToChannel:
    def test_2_4ghz_channels(self):
        """Test 2.4 GHz frequency to channel conversion."""
        assert frequency_to_channel(2412) == 1
        assert frequency_to_channel(2437) == 6
        assert frequency_to_channel(2462) == 11
        assert frequency_to_channel(2484) == 14

    def test_5ghz_channels(self):
        """Test 5 GHz frequency to channel conversion."""
        assert frequency_to_channel(5180) == 36
        assert frequency_to_channel(5240) == 48
        assert frequency_to_channel(5745) == 149
        assert frequency_to_channel(5885) == 177

    def test_6ghz_channels(self):
        """Test 6 GHz frequency to channel conversion."""
        assert frequency_to_channel(5955) == 1
        assert frequency_to_channel(6115) == 33
        assert frequency_to_channel(7115) == 233

    def test_invalid_frequency(self):
        """Invalid frequencies return 0."""
        assert frequency_to_channel(0) == 0
        assert frequency_to_channel(1000) == 0
        assert frequency_to_channel(8000) == 0


class TestParseRadiotapHeader:
    def test_minimal_header(self):
        """Test parsing a minimal radiotap header."""
        # Too short - should return defaults
        result = parse_radiotap_header(b"\x00\x00")
        assert result["rssi"] == -99
        assert result["frequency"] == 0

    def test_header_with_signal(self):
        """Test parsing header with signal strength."""
        # Build a radiotap header with flags, rate, channel, and signal
        present = RT_PRESENT_FLAGS | RT_PRESENT_RATE | RT_PRESENT_CHANNEL | RT_PRESENT_DBM_ANTSIGNAL
        header_len = 16  # 4 (header) + 4 (present) + 1 (flags) + 1 (rate) + 2 (pad) + 4 (channel) + 1 (signal) + padding

        # version, pad, length, present flags
        header = struct.pack("<BBH", 0, 0, header_len)
        header += struct.pack("<I", present)
        # flags (1 byte)
        header += struct.pack("B", 0x10)  # FCS present
        # rate (1 byte)
        header += struct.pack("B", 12)  # 6 Mbps
        # channel (2-byte aligned, so no padding needed after rate at offset 9)
        # Actually need to align to 2 bytes: offset is 10, already aligned
        header += struct.pack("<HH", 5240, 0x0140)  # 5240 MHz, 5GHz OFDM
        # signal (1 byte, signed)
        header += struct.pack("b", -65)
        # pad to header_len
        header += b"\x00" * (header_len - len(header))

        result = parse_radiotap_header(header)
        assert result["header_len"] == header_len
        assert result["fcs_present"] is True
        assert result["rate"] == 6.0
        assert result["frequency"] == 5240
        assert result["channel"] == 48
        assert result["rssi"] == -65

    def test_header_with_tsft(self):
        """Test parsing header with TSFT field (requires 8-byte alignment)."""
        present = RT_PRESENT_TSFT | RT_PRESENT_DBM_ANTSIGNAL
        header_len = 24  # Need enough space for 8-byte aligned TSFT

        header = struct.pack("<BBH", 0, 0, header_len)
        header += struct.pack("<I", present)
        # Pad to 8-byte alignment for TSFT (offset 8 is already 8-byte aligned)
        header += struct.pack("<Q", 123456789)  # TSFT value (8 bytes)
        # signal (1 byte)
        header += struct.pack("b", -50)
        # pad to header_len
        header += b"\x00" * (header_len - len(header))

        result = parse_radiotap_header(header)
        assert result["rssi"] == -50

    def test_invalid_header_length(self):
        """Test handling of invalid header length."""
        # Header claims to be longer than actual data
        header = struct.pack("<BBH", 0, 0, 100)
        header += struct.pack("<I", 0)

        result = parse_radiotap_header(header)
        assert result["rssi"] == -99


class TestPCAPRead:
    def test_read_pcapng_file(self):
        """Test reading a pcapng file."""
        test_dir = Path(__file__).parent
        pcap_file = test_dir / "caps" / "wifi7aruba755-10.7.2.0.pcapng"

        packets = []
        with PCAP(str(pcap_file), mode="r") as pcap:
            for packet in pcap.get_packets():
                packets.append(packet)

        assert len(packets) > 0
        # Each packet tuple: (interface_id, interface_name, timestamp, packet_data)
        interface_id, interface_name, timestamp, packet_data = packets[0]
        assert isinstance(interface_id, int)
        assert isinstance(timestamp, float)
        assert isinstance(packet_data, bytes)

    def test_read_multiple_pcapng_files(self):
        """Test reading different pcapng files."""
        test_dir = Path(__file__).parent

        for pcap_name in ["wifi7aruba755-10.7.2.0.pcapng", "wifi7unifi.pcapng"]:
            pcap_file = test_dir / "caps" / pcap_name
            if pcap_file.exists():
                with PCAP(str(pcap_file), mode="r") as pcap:
                    packets = list(pcap.get_packets())
                    assert len(packets) > 0, f"No packets in {pcap_name}"

    def test_detect_format(self):
        """Test format detection."""
        test_dir = Path(__file__).parent
        pcap_file = test_dir / "caps" / "wifi7aruba755-10.7.2.0.pcapng"

        with PCAP(str(pcap_file), mode="r") as pcap:
            fmt = pcap._detect_format()
            assert fmt == "pcapng"


class TestPCAPHelpers:
    def test_write_option(self):
        """Test option writing with padding."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as f:
            temp_path = f.name

        try:
            with PCAP(temp_path, mode="w") as pcap:
                # Test string option
                opt = pcap._write_option(1, "test")
                # Option: code (2) + len (2) + data (4) + padding (0) = 8 bytes
                assert len(opt) == 8
                assert opt[:2] == struct.pack("<H", 1)  # option code
                assert opt[2:4] == struct.pack("<H", 4)  # length

                # Test option with padding needed
                opt2 = pcap._write_option(2, "abc")  # 3 bytes needs 1 byte padding
                assert len(opt2) == 8  # 2 + 2 + 3 + 1 padding = 8

                # Test empty option (end of options)
                opt_end = pcap._write_option(0)
                assert len(opt_end) == 4
        finally:
            os.unlink(temp_path)

    def test_hex_dump(self):
        """Test hex dump helper."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as f:
            temp_path = f.name

        try:
            with PCAP(temp_path, mode="w") as pcap:
                result = pcap._hex_dump(b"\x00\x01\x02\x03")
                assert "00 01 02 03" in result
                assert "0000:" in result
        finally:
            os.unlink(temp_path)
