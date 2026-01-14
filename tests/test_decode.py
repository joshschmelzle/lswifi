# -*- encoding: utf-8

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestDecodePcap:
    def test_decode_wifi7_pcap_json_output(self):
        """Test decoding a Wi-Fi 7 pcap file produces valid JSON with expected values."""
        # Get the path to the test pcap file relative to this test file
        test_dir = Path(__file__).parent
        pcap_file = test_dir / "caps" / "wifi7aruba755-10.7.2.0.pcapng"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "lswifi",
                "-decode",
                str(pcap_file),
                "--json",
            ],
            capture_output=True,
            text=True,
            cwd=test_dir.parent,  # Run from project root
        )

        # Find the JSON array in stdout (skip log lines)
        stdout_lines = result.stdout.strip().split("\n")
        json_line = None
        for line in stdout_lines:
            if line.startswith("["):
                json_line = line
                break

        assert json_line is not None, "No JSON output found in stdout"

        # 1) Verify output is actual JSON
        data = json.loads(json_line)
        assert isinstance(data, list)
        assert len(data) > 0

        bss = data[0]

        # 2) SSID is "Wi-Fi 7"
        assert bss["ssid"] == "Wi-Fi 7"

        # 3) Channel frequency is 2.412
        assert bss["channel_frequency"] == "2.412"

        # 4) ax and be are in modes
        assert "ax" in bss["modes"]
        assert "be" in bss["modes"]

        # 5) Capable is in PMF
        assert bss["pmf"] == "Capable"

    def test_decode_unifi_pcap_ies_output(self):
        """Test decoding a UniFi pcap file with -ies flag produces expected output."""
        test_dir = Path(__file__).parent
        pcap_file = test_dir / "caps" / "wifi7unifi.pcapng"
        bssid = "9a:2a:6f:42:d4:7a"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "lswifi",
                "-decode",
                str(pcap_file),
                "-ies",
                bssid,
            ],
            capture_output=True,
            text=True,
            cwd=test_dir.parent,
        )

        stdout = result.stdout
        stderr = result.stderr

        # 1) Requested BSSID found in scan results (logged to stderr)
        assert "found requested bssid in the scan results" in stderr.lower()

        # 2) SSID name is UniFi-WPA3-1X
        assert "UniFi-WPA3-1X" in stdout

        # 3) Channel is 48
        assert "[48]" in stdout

        # 4) Frequency is 5.240
        assert "5.240" in stdout

        # 5) 24(B) is one of the rates
        assert "24(B)" in stdout

        # 6) Ubiquiti is in the Vendor output
        assert "Ubiquiti" in stdout
