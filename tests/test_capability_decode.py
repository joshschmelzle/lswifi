# -*- encoding: utf-8

import json
import struct
import subprocess
import sys
from pathlib import Path

from lswifi.__version__ import __version__
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from lswifi.pcap import PCAP, parse_radiotap_header
from tests.test_backends import JSON_KEYS

CAPS = Path(__file__).parent / "caps"
FIVE_GHZ = CAPS / "wifi7unifi.pcapng"


def _bss(ies, mhz=5180):
    return WirelessNetworkBss(
        BssRecord(
            ssid=b"cap",
            bssid="02:00:00:00:00:10",
            frequency_mhz=mhz,
            capability=0x0011,
            ies=ies,
        )
    )


def _tlv(eid, body):
    body = bytes(body)
    return bytes((eid, len(body))) + body


def _ext(body):
    return _tlv(255, body)


def _ie_text(bss, name):
    lines = []
    capture = False
    for ie in bss.information_elements:
        if ie.name == name:
            capture = True
            lines.append(ie.decoded)
            continue
        if capture:
            if ie.eid == "" and ie.decoded:
                lines.append(ie.decoded)
                continue
            break
    return "\n".join(lines)


def _first_beacon(path):
    with PCAP(str(path), mode="r") as pcap:
        for _interface_id, _name, _timestamp, packet in pcap.get_packets():
            rt = parse_radiotap_header(packet)
            frame = packet[rt["header_len"] :]
            if len(frame) < 36:
                continue
            frame_control = struct.unpack("<H", frame[:2])[0]
            frame_type = (frame_control & 0x000C) >> 2
            frame_subtype = (frame_control & 0x00F0) >> 4
            if frame_type != 0 or frame_subtype != 8:
                continue
            if rt["fcs_present"] and len(frame) > 40:
                ies = frame[36:-4]
            else:
                ies = frame[36:]
            return rt["frequency"], bytes(ies)
    raise AssertionError(f"no beacon in {path}")


def _capture_bss(path):
    frequency, ies = _first_beacon(path)
    return _bss(ies, frequency)


def _vht(cap, rx_map=0xFFFF, tx_map=0xFFFF, tx_highest=b"\x00\x00"):
    body = (
        cap.to_bytes(4, "little")
        + rx_map.to_bytes(2, "little")
        + b"\x00\x00"
        + tx_map.to_bytes(2, "little")
        + tx_highest
    )
    return _tlv(191, body)


def _he_capabilities(mac0=0, phy0=0, phy2=0, phy3=0, phy4=0):
    phy = bytes([phy0, 0, phy2, phy3, phy4]) + bytes(6)
    body = bytes([35, mac0]) + bytes(5) + phy + bytes(4)
    return _ext(body)


def _he_operation(params0=0, params2=0, color=0, six_ghz=b""):
    body = bytes([36, params0, 0, params2, color, 0, 0]) + six_ghz
    return _ext(body)


def _ht_capabilities(info):
    body = info.to_bytes(2, "little") + bytes(24)
    body = bytearray(body)
    body[3] = 0xFF
    body[4] = 0xFF
    return _tlv(45, bytes(body))


def _ht_operation(primary, ht_param, operation_mode):
    body = bytes([primary, ht_param]) + operation_mode.to_bytes(2, "little") + bytes(18)
    return _tlv(61, body)


class TestVhtCapabilities:
    def test_fixture_decodes_capabilities_and_mcs_maps(self):
        text = _ie_text(_capture_bss(FIVE_GHZ), "VHT Capabilities")
        assert text == "\n".join(
            [
                "VHT Capabilities Info: 0x338bf9f6",
                "  Max MPDU Length: 11454",
                "  Supported Channel Width Set: 160 MHz",
                "  Rx LDPC: 1",
                "  Short GI for 80 MHz: 1",
                "  Short GI for 160 MHz and 80+80 MHz: 1",
                "  Tx STBC: 1",
                "  Rx STBC: 1 SS",
                "  SU Beamformer: 1",
                "  SU Beamformee: 1",
                "  MU Beamformer: 1",
                "  MU Beamformee: 0",
                "  Extended NSS BW: 0",
                "MCS Set",
                "  Rx MCS Map: 0xffaa",
                "    0b1111111110101010",
                "    Rx 1 SS: MCS 0-9",
                "    Rx 2 SS: MCS 0-9",
                "    Rx 3 SS: MCS 0-9",
                "    Rx 4 SS: MCS 0-9",
                "    Rx 5 SS: not supported",
                "    Rx 6 SS: not supported",
                "    Rx 7 SS: not supported",
                "    Rx 8 SS: not supported",
                "  Tx MCS Map: 0xffaa",
                "    0b1111111110101010",
                "    Tx 1 SS: MCS 0-9",
                "    Tx 2 SS: MCS 0-9",
                "    Tx 3 SS: MCS 0-9",
                "    Tx 4 SS: MCS 0-9",
                "    Tx 5 SS: not supported",
                "    Tx 6 SS: not supported",
                "    Tx 7 SS: not supported",
                "    Tx 8 SS: not supported",
            ]
        )
        assert "VHT Operation Info" not in text
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("0b"):
                assert "0x" not in stripped
                assert len(stripped) == 18

    def test_capability_bits(self):
        cases = (
            (0x00000000, "Max MPDU Length: 3895"),
            (0x00000001, "Max MPDU Length: 7991"),
            (0x00000002, "Max MPDU Length: 11454"),
            (0x00000003, "Max MPDU Length: reserved"),
            (0x00000000, "Supported Channel Width Set: neither 160 MHz nor 80+80"),
            (0x00000004, "Supported Channel Width Set: 160 MHz"),
            (0x00000008, "Supported Channel Width Set: 160 MHz and 80+80"),
            (0x0000000C, "Supported Channel Width Set: reserved"),
            (0x00000010, "Rx LDPC: 1"),
            (0x00000020, "Short GI for 80 MHz: 1"),
            (0x00000040, "Short GI for 160 MHz and 80+80 MHz: 1"),
            (0x00000080, "Tx STBC: 1"),
            (0x00000100, "Rx STBC: 1 SS"),
            (0x00000200, "Rx STBC: 1-2 SS"),
            (0x00000300, "Rx STBC: 1-3 SS"),
            (0x00000400, "Rx STBC: 1-4 SS"),
            (0x00000500, "Rx STBC: reserved"),
            (0x00000800, "SU Beamformer: 1"),
            (0x00001000, "SU Beamformee: 1"),
            (0x00080000, "MU Beamformer: 1"),
            (0x00100000, "MU Beamformee: 1"),
            (0x40000000, "Extended NSS BW: 1"),
            (0x80000000, "Extended NSS BW: 2"),
            (0xC0000000, "Extended NSS BW: 3"),
        )
        for cap, expected in cases:
            text = _ie_text(_bss(_vht(cap)), "VHT Capabilities")
            assert expected in [line.strip() for line in text.splitlines()]

    def test_mcs_map_keeps_leading_zeros_and_rx_tx_order(self):
        text = _ie_text(
            _bss(_vht(0, rx_map=0x0002, tx_map=0xFF00, tx_highest=b"\x00\x20")),
            "VHT Capabilities",
        )
        assert "  Rx MCS Map: 0x0002" in text
        assert "    0b0000000000000010" in text
        assert "    Rx 1 SS: MCS 0-9" in text
        assert "    Rx 2 SS: MCS 0-7" in text
        assert "    Rx 8 SS: MCS 0-7" in text
        assert "  Tx MCS Map: 0xff00" in text
        assert "    0b1111111100000000" in text
        assert "    Tx 1 SS: MCS 0-7" in text
        assert "    Tx 4 SS: MCS 0-7" in text
        assert "    Tx 5 SS: not supported" in text
        assert "    Tx 8 SS: not supported" in text
        binary = [
            line.strip() for line in text.splitlines() if line.strip().startswith("0b")
        ]
        assert binary == ["0b0000000000000010", "0b1111111100000000"]
        assert all("0x" not in line for line in binary)

    def test_each_mcs_value(self):
        # SS1 MCS 0-7, SS2 MCS 0-8, SS3 MCS 0-9, SS4 not supported, rest MCS 0-7
        rx_map = 0x00E4
        text = _ie_text(_bss(_vht(0, rx_map=rx_map, tx_map=0xFFFF)), "VHT Capabilities")
        assert "    Rx 1 SS: MCS 0-7" in text
        assert "    Rx 2 SS: MCS 0-8" in text
        assert "    Rx 3 SS: MCS 0-9" in text
        assert "    Rx 4 SS: not supported" in text
        assert "    Tx 1 SS: not supported" in text

    def test_short_element_stays_inside_the_element(self):
        bss = _bss(_tlv(191, b"\x01\x02"))
        assert _ie_text(bss, "VHT Capabilities") == "truncated (raw 01 02)"
        assert bss.channel_width.value == 20

    def test_capabilities_do_not_set_channel_width(self):
        bss = _bss(_vht(0x338BF9F6, rx_map=0xFFAA, tx_map=0xFFAA))
        assert bss.channel_width.value == 20
        assert "ac" in bss.modes


class TestHeCapabilities:
    def test_fixture_lists_beamforming_capabilities(self):
        text = _ie_text(_capture_bss(FIVE_GHZ), "Extension: (35) HE Capabilities")
        assert text == (
            "+HTC HE Supported, TWT Responder, BSR Supported, "
            "Full BW UL MU-MIMO, SU Beamformer, MU Beamformer"
        )
        assert "TWT Requester" not in text

    def test_twt_requester_and_beamforming_bits(self):
        requester = _ie_text(
            _bss(_he_capabilities(mac0=0x02)), "Extension: (35) HE Capabilities"
        )
        assert requester == "TWT Requester"

        both = _ie_text(
            _bss(_he_capabilities(mac0=0x07)), "Extension: (35) HE Capabilities"
        )
        assert both == "+HTC HE Supported, TWT Requester, TWT Responder"

        phy = _ie_text(
            _bss(_he_capabilities(phy0=0x40, phy2=0x40, phy3=0x80, phy4=0x02)),
            "Extension: (35) HE Capabilities",
        )
        assert phy == (
            "242 tone RU supported, Full BW UL MU-MIMO, SU Beamformer, MU Beamformer"
        )

        clear = _ie_text(_bss(_he_capabilities()), "Extension: (35) HE Capabilities")
        assert clear == ""

    def test_twt_required_is_a_capability_and_bss_color_stays(self):
        required = _ie_text(
            _bss(_he_operation(params0=0x08, color=0xC5)),
            "Extension: (36) HE Operation",
        )
        assert required == (
            "BSS Color: 5, Partial BSS Color: 1, BSS Color Disabled: 1, TWT Required"
        )

        clear = _ie_text(
            _bss(_he_operation(color=0xC5)),
            "Extension: (36) HE Operation",
        )
        assert clear == "BSS Color: 5, Partial BSS Color: 1, BSS Color Disabled: 1"
        assert "TWT Required" not in clear

        six = _ie_text(
            _bss(
                _he_operation(
                    params0=0x08,
                    params2=0x02,
                    six_ghz=bytes([37, 0x01, 39, 0, 6]),
                )
            ),
            "Extension: (36) HE Operation",
        )
        assert six.startswith(
            "BSS Color: 0, Partial BSS Color: 0, BSS Color Disabled: 0, "
            "TWT Required, 6G Channel: 37"
        )

    def test_fixture_bss_color_without_twt_required(self):
        text = _ie_text(_capture_bss(FIVE_GHZ), "Extension: (36) HE Operation")
        assert text == "BSS Color: 42, Partial BSS Color: 0, BSS Color Disabled: 0"


class TestHtCapabilities:
    def test_fixture_fields(self):
        bss = _capture_bss(FIVE_GHZ)
        assert _ie_text(bss, "HT Capabilities") == "\n".join(
            [
                "Supported Channel Width Set: True",
                "LDPC: True",
                "SGI 20: True",
                "SGI 40: True",
                "Tx STBC: True",
                "Rx STBC: 1 SS",
                "40 MHz Intolerant: False",
                "Spatial Streams: 4",
            ]
        )
        assert bss.spatial_streams.value == 4
        assert _ie_text(bss, "HT Operation") == (
            "Primary Channel: 48, HT Channel Width: False, "
            "Secondary Channel Offset: 0, HT Protection: No protection mode, "
            "Non-greenfield STAs Present: False, CCFS2: 0"
        )
        assert str(bss.channel_width.value) == "20"

    def test_capability_bits(self):
        cases = (
            (0x0001, "LDPC: True", "LDPC: False"),
            (0x0020, "SGI 20: True", "SGI 20: False"),
            (0x0040, "SGI 40: True", "SGI 40: False"),
            (0x0080, "Tx STBC: True", "Tx STBC: False"),
            (0x0100, "Rx STBC: 1 SS", None),
            (0x0200, "Rx STBC: 1-2 SS", None),
            (0x0300, "Rx STBC: 1-3 SS", None),
            (0x0000, "Rx STBC: not supported", None),
            (0x4000, "40 MHz Intolerant: True", "40 MHz Intolerant: False"),
        )
        for info, present, absent in cases:
            text = _ie_text(_bss(_ht_capabilities(info), 2412), "HT Capabilities")
            assert present in text.splitlines()
            if absent:
                assert absent not in text.splitlines()
        zero = _ie_text(_bss(_ht_capabilities(0), 2412), "HT Capabilities")
        assert "Supported Channel Width Set: False" in zero
        assert "Spatial Streams: 2" in zero

    def test_operation_protection_non_greenfield_and_ccfs2(self):
        cases = (
            (b"\x00\x00", "No protection mode", "False", "0"),
            (b"\x01\x00", "HT non-member protection mode", "False", "0"),
            (b"\x02\x00", "20 MHz protection mode", "False", "0"),
            (b"\x03\x00", "non-HT mixed mode", "False", "0"),
            (b"\x04\x00", "No protection mode", "True", "0"),
            (b"\x47\x06", "non-HT mixed mode", "True", "50"),
            (b"\xe0\x1f", "No protection mode", "False", "255"),
        )
        for mode, protection, non_gf, ccfs2 in cases:
            body = bytes([48, 0x00]) + mode + bytes(18)
            text = _ie_text(_bss(_tlv(61, body)), "HT Operation")
            assert text == (
                "Primary Channel: 48, HT Channel Width: False, "
                "Secondary Channel Offset: 0, "
                f"HT Protection: {protection}, "
                f"Non-greenfield STAs Present: {non_gf}, CCFS2: {ccfs2}"
            )

    def test_operation_text_does_not_change_channel_width(self):
        body = bytes([1, 0x05, 0x47, 0x06]) + bytes(18)
        bss = _bss(_tlv(61, body), 2412)
        assert bss.channel_width.value == "40"
        assert bss.channel_marking == "+"
        text = _ie_text(bss, "HT Operation")
        assert "HT Protection: non-HT mixed mode" in text
        assert "CCFS2: 50" in text


# Captured before the text-only decode change. Timestamp is the wall clock.
FIVE_GHZ_JSON_ROW = {
    "amendments": ["d", "e", "h", "i", "k", "r", "v", "w"],
    "apname": "",
    "bss_type": "Infrastructure",
    "bssid": "9a:2a:6f:42:d4:7a",
    "channel_frequency": "5.240",
    "channel_number": "48",
    "channel_width": "20",
    "connected": False,
    "country_code": "US",
    "ies": [
        0,
        1,
        5,
        7,
        11,
        32,
        35,
        45,
        48,
        54,
        61,
        70,
        127,
        191,
        192,
        195,
        201,
        221,
        221,
        221,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
    ],
    "ies_extension": ["35", "36", "38", "39", "106", "107", "108", "110"],
    "interface_mac": "pcap file",
    "modes": ["ac", "ax", "be", "n"],
    "phy_type": "be",
    "pmf": "Required",
    "rates_basic": ["6", "12", "24"],
    "rates_data": ["9", "18", "36", "48", "54"],
    "rssi": "-61",
    "security": "FT-.1X-SHA-256,.1X-SHA-256/CCMP-128/CCMP-128",
    "spatial_streams": "4",
    "ssid": "UniFi-WPA3-1X",
    "stations": "0",
    "uptime": None,
    "utilization": "4%",
}


def test_fixture_json_output_is_unchanged(tmp_path):
    out = tmp_path / "out.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "lswifi",
            "-decode",
            str(FIVE_GHZ),
            "--json",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(out.read_text())
    assert list(document) == ["lswifi", "scan_data"]
    assert document["lswifi"] == {"version": f"lswifi {__version__}"}
    assert len(document["scan_data"]) == 1
    row = document["scan_data"][0]
    assert isinstance(row.pop("timestamp"), str)
    assert set(row) == JSON_KEYS - {"timestamp"}
    assert row == FIVE_GHZ_JSON_ROW
    printed = json.loads(result.stdout)
    assert isinstance(printed, list)
    assert len(printed) == 1
    assert isinstance(printed[0].pop("timestamp"), str)
    assert printed == [row]
