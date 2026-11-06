from ctypes import POINTER, cast, create_string_buffer

import pytest

from lswifi.elements import WirelessNetworkBss, iter_elements

SSID = bytes([0, 4]) + b"test"
RATES = bytes([1, 2, 0x8C, 0x12])
WMM = bytes.fromhex("dd180050f2020101800003a4000027a4000042435e0062322f00")


@pytest.mark.parametrize(
    ("data", "elements"),
    [
        (b"", []),
        (SSID, [(0, 4, b"test")]),
        (SSID + RATES, [(0, 4, b"test"), (1, 2, b"\x8c\x12")]),
        (bytes([0, 0]) + RATES, [(0, 0, b""), (1, 2, b"\x8c\x12")]),
        (SSID + b"\x00", [(0, 4, b"test")]),
        (SSID + bytes([1, 4, 0x8C]), [(0, 4, b"test"), (1, 4, b"\x8c")]),
        (SSID + bytes([1, 4]), [(0, 4, b"test")]),
    ],
)
def test_iter_elements(data, elements):
    assert list(iter_elements(data)) == elements


def test_iter_elements_reads_a_ctypes_buffer_with_its_trailing_nul():
    buffer = create_string_buffer(SSID + RATES)
    contents = cast(buffer, POINTER(type(buffer))).contents
    assert [eid for eid, _length, _body in iter_elements(contents)] == [0, 1]


def test_decoded_file_formats_the_last_element_like_the_others():
    ies = WirelessNetworkBss.decode_bytefile_ies(bytearray(SSID + WMM + RATES + WMM))
    headers = [ie for ie in ies if ie.eid != ""]
    assert [ie.eid for ie in headers] == [0, 221, 1, 221]
    assert [ie.length for ie in headers] == [
        "4 bytes",
        "24 bytes",
        "2 bytes",
        "24 bytes",
    ]
    rows_per_wmm = len(ies[1 : ies.index(headers[2])])
    assert len(ies[ies.index(headers[3]) :]) == rows_per_wmm
