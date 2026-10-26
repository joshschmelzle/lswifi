# -*- encoding: utf-8

import json
import sys

import pytest

import lswifi
import lswifi.elements
from lswifi import app
from lswifi.backends.base import BssRecord
from tests.test_backends import ARUBA, JSON_KEYS, UNIFI, Session, parse

# WirelessNetworkBss


def _bss_with_ies(ssid, ie_bytes, capability=0x0011):
    ies = bytes([0, len(ssid)]) + ssid + bytes([1, 1, 0x82]) + ie_bytes
    return lswifi.elements.WirelessNetworkBss(
        BssRecord(
            ssid=ssid,
            bssid="02:00:00:00:00:10",
            frequency_mhz=2437,
            capability=capability,
            ies=ies,
        )
    )


class TestElements:
    def test_parse_rates(self):
        test1 = lswifi.elements.OutObject(
            value="1(b) 2(b) 5.5(b) 11(b) 6(b) 9 12(b) 18 24(b) 36 48 54"
        )

        test2 = lswifi.elements.OutObject(
            value="1(b) 2(b) 5.5(b) 11(b) 18 24 36 54 6 9 12 48"
        )

        test3 = lswifi.elements.OutObject(value="6(b) 9 12(b) 18 24(b) 36 48 54")

        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test1)
            == "1(B) 2(B) 5.5(B) 6(B) 9 11(B) 12(B) 18 24(B) 36 48 54"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test2)
            == "1(B) 2(B) 5.5(B) 6 9 11(B) 12 18 24 36 48 54"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.parse_rates(test3)
            == "6(B) 9 12(B) 18 24(B) 36 48 54"
        )

    def test_convert_timestamp_to_uptime(self):
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(
                13667420576596
            )
            == "158d 4:30:20"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(179295494144)
            == "02d 1:48:15"
        )
        assert (
            lswifi.elements.WirelessNetworkBss.convert_timestamp_to_uptime(285837076)
            == "00d 0:04:45"
        )

    @pytest.mark.parametrize(
        "wpa_ie, auth, encryption, security",
        [
            pytest.param(
                "dd160050f20101000050f20201000050f20201000050f202",
                "PSK",
                "TKIP",
                "PSK/TKIP/TKIP",
                id="wpa-psk-tkip",
            ),
            pytest.param(
                "dd160050f20101000050f20401000050f20401000050f201",
                ".1X-SHA-1",
                "CCMP-128",
                ".1X-SHA-1/CCMP-128/CCMP-128",
                id="wpa-1x-ccmp",
            ),
        ],
    )
    def test_legacy_wpa_ie(self, wpa_ie, auth, encryption, security):
        bss = _bss_with_ies(b"legacy", bytes.fromhex(wpa_ie))
        assert (str(bss.auth), str(bss.encryption), str(bss.security)) == (
            auth,
            encryption,
            security,
        )
        decoded = next(ie.decoded for ie in bss.information_elements if ie.eid == 221)
        assert decoded.startswith("Microsoft WPA Version: 1,")
        assert auth in decoded
        assert encryption.split("/")[0] in decoded

    def test_legacy_wpa_alongside_rsn(self):
        rsn = bytes.fromhex("30140100000fac020100000fac040100000fac020000")
        wpa = bytes.fromhex("dd160050f20101000050f20201000050f20201000050f202")
        bss = _bss_with_ies(b"mixed", rsn + wpa)
        assert str(bss.auth) == "PSK"
        assert str(bss.encryption) == "CCMP-128,TKIP/TKIP"
        assert str(bss.security) == "PSK/CCMP-128,TKIP/TKIP"
        decoded = next(ie.decoded for ie in bss.information_elements if ie.eid == 221)
        assert "TKIP" in decoded and "PSK" in decoded

    def test_short_extended_capabilities_does_not_crash(self):
        bss = _bss_with_ies(b"short", bytes([127, 2, 0x00, 0x00]))
        assert "v" not in bss.amendments
        bss = _bss_with_ies(b"btm", bytes([127, 3, 0x00, 0x00, 0x08]))
        assert "v" in bss.amendments

    def test_short_vendor_ie_does_not_crash(self):
        bss = _bss_with_ies(b"short", bytes([221, 2, 0x00, 0x50]))
        decoded = next(ie.decoded for ie in bss.information_elements if ie.eid == 221)
        assert decoded == "truncated vendor IE"


def _ext(body):
    return bytes([255, len(body)]) + body


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


class TestExtensionElements:
    def test_empty_extension_element_keeps_the_rest_of_the_ie_list(self):
        bss = _bss_with_ies(b"empty", bytes([255, 0, 3, 1, 8]))
        ext = next(ie for ie in bss.information_elements if ie.eid == 255)
        assert ext.name == "Extension"
        assert "None" not in ext.name
        assert ext.decoded == "truncated extension element"
        assert list(bss.exie_numbers) == []
        assert 3 in [ie.eid for ie in bss.information_elements]

    def test_trailing_empty_extension_element(self):
        bss = _bss_with_ies(b"empty", bytes([255, 0]))
        ext = [ie for ie in bss.information_elements if ie.eid == 255]
        assert len(ext) == 1
        assert ext[0].name == "Extension"
        assert ext[0].decoded == "truncated extension element"

    def test_unknown_extension_id_shows_number_and_body_hex(self):
        bss = _bss_with_ies(b"unk", _ext(bytes.fromhex("97dead")))
        ext = next(ie for ie in bss.information_elements if ie.eid == 255)
        assert ext.name == "Extension 151"
        assert ext.decoded == (
            "Parser not implemented. Contact developer if you want this supported. "
            "97 DE AD"
        )
        assert list(bss.exie_numbers) == ["151"]
        assert "Extension 151" in str(bss)
        assert "97 DE AD" in str(bss)

    def test_truncated_extension_does_not_drop_later_elements(self):
        ies = _ext(bytes.fromhex("6a01")) + _ext(bytes.fromhex("23")) + bytes([3, 1, 8])
        bss = _bss_with_ies(b"short", ies)
        eids = [ie.eid for ie in bss.information_elements if ie.eid != ""]
        assert eids.count(255) == 2
        assert 3 in eids
        eht = _ie_text(bss, "Extension: (106) EHT Operation")
        assert "Operation Information Present: 1" in eht
        assert "MCS 15 Disable: 0" in eht
        assert "Basic EHT-MCS" not in eht
        assert "Channel Width:" not in eht
        assert "truncated" in eht
        he = _ie_text(bss, "Extension: (35) HE Capabilities")
        assert he.startswith("truncated (raw ")
        assert "23" in he
        assert "be" in bss.modes

    def test_truncated_eht_operation_keeps_complete_fields(self):
        partial_mcs = _bss_with_ies(b"mcs", _ext(bytes.fromhex("6a0111")))
        text = _ie_text(partial_mcs, "Extension: (106) EHT Operation")
        assert "EHT Operation Parameters: 0x01" in text
        assert "truncated (raw 11)" in text
        assert "Basic EHT-MCS" not in text

        partial_info = _bss_with_ies(b"info", _ext(bytes.fromhex("6a011100000004")))
        text = _ie_text(partial_info, "Extension: (106) EHT Operation")
        assert "Basic EHT-MCS And NSS Set: 11 00 00 00" in text
        assert "MCS 0-7: Rx 1 SS, Tx 1 SS" in text
        assert "truncated (raw 04)" in text
        assert "Channel Width:" not in text
        assert partial_info.channel_width.value == 20

        short_bitmap = _bss_with_ies(
            b"bitmap", _ext(bytes.fromhex("6a0311000000040f1f02"))
        )
        text = _ie_text(short_bitmap, "Extension: (106) EHT Operation")
        assert "Channel Width: 320 MHz, CCFS 0: 15, CCFS 1: 31" in text
        assert "truncated (raw 02)" in text
        assert "Disabled Subchannel Bitmap: 0x" not in text
        assert short_bitmap.channel_width.value == "320"

    def test_eht_operation_parameter_bits_and_mcs_nss(self):
        bss = _bss_with_ies(b"bits", _ext(bytes.fromhex("6a7c11000000")))
        text = _ie_text(bss, "Extension: (106) EHT Operation")
        assert "EHT Operation Parameters: 0x7c" in text
        assert "Operation Information Present: 0" in text
        assert "Disabled Subchannel Bitmap Present: 0" in text
        assert "Default PE Duration: 1" in text
        assert "Group Addressed BU Indication Limit: 1" in text
        assert "Group Addressed BU Indication Exponent: 3" in text
        assert "MCS 15 Disable: 1 (MCS 15 disabled)" in text
        assert "Basic EHT-MCS And NSS Set: 11 00 00 00" in text
        assert "MCS 0-7: Rx 1 SS, Tx 1 SS" in text
        assert "MCS 8-9: not supported" in text
        assert "MCS 10-11: not supported" in text
        assert "MCS 12-13: not supported" in text
        assert "Channel Width:" not in text
        assert "truncated" not in text
        assert bss.channel_width.value == 20

    def test_bitmap_without_operation_info_is_not_decoded(self):
        bss = _bss_with_ies(b"nobitmap", _ext(bytes.fromhex("6a02110000000200")))
        text = _ie_text(bss, "Extension: (106) EHT Operation")
        assert "Disabled Subchannel Bitmap Present: 1" in text
        assert "Operation Information Present: 0" in text
        assert "Disabled Subchannel Bitmap: 0x" not in text
        assert "Channel Width:" not in text
        assert "truncated" not in text
        assert bss.channel_width.value == 20

    @pytest.mark.parametrize(
        "body, width, bitmap, punctured",
        [
            ("6a0300000000040f1f0200", "320", "0x0002", "1"),
            ("6a03000000000300000500", "160", "0x0005", "0, 2"),
        ],
    )
    def test_disabled_subchannel_bitmap(self, body, width, bitmap, punctured):
        bss = _bss_with_ies(b"puncture", _ext(bytes.fromhex(body)))
        text = _ie_text(bss, "Extension: (106) EHT Operation")
        assert f"Channel Width: {width} MHz, CCFS 0:" in text
        if bitmap == "0x0002":
            assert "Channel Width: 320 MHz, CCFS 0: 15, CCFS 1: 31" in text
        assert (
            f"Disabled Subchannel Bitmap: {bitmap} "
            f"(punctured 20 MHz subchannels: {punctured})"
        ) in text
        assert "truncated" not in text
        assert bss.channel_width.value == width

    def test_zero_bitmap_reports_no_punctured_subchannels(self):
        bss = _bss_with_ies(b"full", _ext(bytes.fromhex("6a0300000000020f1f0000")))
        text = _ie_text(bss, "Extension: (106) EHT Operation")
        assert "Channel Width: 80 MHz, CCFS 0: 15, CCFS 1: 31" in text
        assert (
            "Disabled Subchannel Bitmap: 0x0000 (no 20 MHz subchannels punctured)"
            in text
        )

    def test_wifi7_fixture_eht_operation(self):
        aruba = lswifi.elements.WirelessNetworkBss(BssRecord(**ARUBA))
        text = _ie_text(aruba, "Extension: (106) EHT Operation")
        assert "EHT Operation Parameters: 0x40" in text
        assert "MCS 15 Disable: 1 (MCS 15 disabled)" in text
        assert "Operation Information Present: 0" in text
        assert "Default PE Duration: 0" in text
        assert "Group Addressed BU Indication Exponent: 0" in text
        assert "Basic EHT-MCS And NSS Set: 11 00 00 00" in text
        assert "MCS 0-7: Rx 1 SS, Tx 1 SS" in text
        assert "Channel Width:" not in text
        assert aruba.channel_width.value == "20"
        assert "MCS 15 disabled" in str(aruba)
        assert "Extension: (106) EHT Operation" in str(aruba)

        unifi = lswifi.elements.WirelessNetworkBss(BssRecord(**UNIFI))
        text = _ie_text(unifi, "Extension: (106) EHT Operation")
        assert "EHT Operation Parameters: 0x04" in text
        assert "Default PE Duration: 1" in text
        assert "MCS 15 Disable: 0" in text
        assert "MCS 15 disabled" not in text
        assert "Basic EHT-MCS And NSS Set: 11 00 00 00" in text
        assert "Channel Width:" not in text

    def test_malformed_extension_json_stays_one_document(self, tmp_path, capsys):
        ies = (
            bytes([255, 0])
            + _ext(bytes.fromhex("6a01"))
            + _ext(bytes.fromhex("97aa"))
            + bytes([3, 1, 8])
        )
        bss = _bss_with_ies(b"mix", ies)
        path = tmp_path / "out.json"
        args = parse(["--json", str(path)])
        scanner = app.lswifi()
        out, _rnr, length, bssids, names, json_out, new = scanner.parse_bss_list(
            Session([bss]), False, "", str(path), args
        )
        scanner.print_bss_list(
            out, length, "00:11:22:33:44:55", bssids, False, names, json_out, new, args
        )
        printed = json.loads(capsys.readouterr().out)
        assert printed == json_out
        document = json.loads(path.read_text())
        assert set(document) == {"lswifi", "scan_data"}
        assert document["scan_data"] == json_out
        row = document["scan_data"][0]
        assert set(row) == JSON_KEYS
        assert isinstance(row["ies"], list)
        assert isinstance(row["ies_extension"], list)
        assert all(isinstance(item, str) for item in row["ies_extension"])
        assert "106" in row["ies_extension"]
        assert "151" in row["ies_extension"]
        assert 255 in row["ies"]
        assert 3 in row["ies"]
