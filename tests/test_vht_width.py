import json

import pytest

from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from tests.test_backends import JSON_KEYS, json_rows


def _bss(ssid, ies, mhz=5180):
    wrapped = bytes([0, len(ssid)]) + ssid + bytes([1, 1, 0x8C]) + ies
    return WirelessNetworkBss(
        BssRecord(
            ssid=ssid,
            bssid="02:00:00:00:00:10",
            frequency_mhz=mhz,
            ies=wrapped,
        )
    )


def _vht_op(width, ccfs0, ccfs1):
    body = bytes([width, ccfs0, ccfs1, 0xFF, 0xFF])
    return bytes([192, len(body)]) + body


def _vht_cap(supp_chwidth=0, ext_nss_bw=0):
    info = ((supp_chwidth & 0x3) << 2) | ((ext_nss_bw & 0x3) << 30)
    body = info.to_bytes(4, "little") + bytes(8)
    return bytes([191, len(body)]) + body


def _ht_op(primary=36, ht_param=0, ccfs2=0):
    operation_mode = (ccfs2 & 0xFF) << 5
    body = bytes(
        [
            primary & 0xFF,
            ht_param & 0xFF,
            operation_mode & 0xFF,
            (operation_mode >> 8) & 0xFF,
        ]
    )
    body += bytes(18)
    return bytes([61, len(body)]) + body


def _he_operation_6ghz(ccfs0, ccfs1, control=0x03):
    body = bytes([36, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
    body += bytes([5, control, ccfs0, ccfs1, 6])
    return bytes([255, len(body)]) + body


def _width_text(bss):
    for ie in bss.information_elements:
        if ie.eid == 255 and "Width:" in ie.decoded:
            return ie.decoded
    return ""


class TestVhtOperatingWidth:
    def test_width_1_center_gap_8_is_160(self):
        assert _bss(b"vht", _vht_op(1, 42, 50)).channel_width.value == "160"
        capable = _vht_cap(supp_chwidth=1) + _vht_op(1, 42, 50)
        assert _bss(b"vht", capable).channel_width.value == "160"

    def test_deprecated_width_2_is_160(self):
        bss = _bss(b"vht", _vht_op(2, 50, 0))
        assert bss.channel_width.value == "160"

    def test_width_1_larger_center_gap_is_80_plus_80(self):
        assert _bss(b"vht", _vht_op(1, 42, 155)).channel_width.value == "80+80"
        capable = _vht_cap(supp_chwidth=2) + _vht_op(1, 42, 155)
        assert _bss(b"vht", capable).channel_width.value == "80+80"

    def test_deprecated_width_3_is_80_plus_80(self):
        bss = _bss(b"vht", _vht_op(3, 42, 155))
        assert bss.channel_width.value == "80+80"

    @pytest.mark.parametrize("ext_nss_bw", [1, 2, 3])
    def test_ext_nss_bw_takes_160_center_from_ht_ccfs2(self, ext_nss_bw):
        ies = _ht_op(ccfs2=50) + _vht_cap(ext_nss_bw=ext_nss_bw) + _vht_op(1, 42, 0)
        bss = _bss(b"vht", ies)
        assert bss.channel_width.value == "160"

    def test_supported_160_with_ext_nss_bw_still_uses_ht_ccfs2(self):
        ies = _ht_op(ccfs2=50) + _vht_cap(supp_chwidth=1, ext_nss_bw=1)
        ies += _vht_op(1, 42, 0)
        assert _bss(b"vht", ies).channel_width.value == "160"

    @pytest.mark.parametrize(
        "width, ccfs0, ccfs1",
        [(1, 42, 0), (1, 42, 50), (2, 50, 0)],
    )
    def test_24ghz_bss_does_not_take_vht_width(self, width, ccfs0, ccfs1):
        bss = _bss(b"n", _vht_op(width, ccfs0, ccfs1), mhz=2437)
        assert bss.channel_width.value == 20

    def test_24ghz_keeps_ht_40(self):
        ies = _ht_op(primary=6, ht_param=0x01) + _vht_op(1, 42, 50)
        bss = _bss(b"n", ies, mhz=2437)
        assert bss.channel_width.value == "40"


class TestHe6GHzWidthCode3:
    def test_ccfs1_zero_is_80(self):
        bss = _bss(b"he", _he_operation_6ghz(7, 0), mhz=5975)
        assert bss.channel_width.value == "80"
        assert "Width: 80 MHz" in _width_text(bss)

    def test_odd_gap_is_80_plus_80(self):
        bss = _bss(b"he", _he_operation_6ghz(7, 14), mhz=5975)
        assert bss.channel_width.value == "80+80"
        assert "Width: 80+80 MHz" in _width_text(bss)


def test_json_keeps_one_document_and_80_plus_80_string(tmp_path):
    record = BssRecord(
        ssid=b"wide",
        bssid="02:00:00:00:00:21",
        frequency_mhz=5180,
        ies=bytes([0, 4]) + b"wide" + bytes([1, 1, 0x8C]) + _vht_op(1, 42, 155),
    )
    rows = json_rows([record], tmp_path)
    assert rows[0]["channel_width"] == "80+80"
    assert set(rows[0]) == JSON_KEYS

    text = (tmp_path / "out.json").read_text()
    document = json.loads(text)
    assert list(document) == ["lswifi", "scan_data"]
    assert isinstance(document["scan_data"], list)
    assert document["scan_data"][0]["channel_width"] == "80+80"
    assert set(document["scan_data"][0]) == JSON_KEYS
