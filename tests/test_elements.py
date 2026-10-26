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

    def test_wifi7_fixture_eht_capabilities_and_multi_link(self):
        unifi = lswifi.elements.WirelessNetworkBss(BssRecord(**UNIFI))
        eht = _ie_text(unifi, "Extension: (108) EHT Capabilities")
        assert "EHT MAC Capabilities: 07 00" in eht
        assert "EPCS Priority Access: 1" in eht
        assert "OM Control: 1" in eht
        assert "EHT TRS: 0" in eht
        assert "TXOP Return Support: 0" in eht
        assert "Max MPDU Length: 3895" in eht
        assert "Max A-MPDU Length Exponent Extension: 0" in eht
        assert "320 MHz In 6 GHz: 0" in eht
        assert "242-tone RU In BW Wider Than 20 MHz: 0" in eht
        assert "NDP With 4x EHT-LTF And 3.2 us GI: 0" in eht
        assert "SU Beamformer: 1" in eht
        assert "SU Beamformee: 1" in eht
        assert "Beamformee SS <= 80 MHz: 8 SS" in eht
        assert "Beamformee SS 160 MHz: 8 SS" in eht
        assert "Beamformee SS 320 MHz: reserved" in eht
        assert "Sounding Dimensions <= 80 MHz: 4 SS" in eht
        assert "Sounding Dimensions 160 MHz: 4 SS" in eht
        assert "Partial Bandwidth UL MU-MIMO: 0" in eht
        assert "Partial Bandwidth DL MU-MIMO: 0" in eht
        assert "EHT MU PPDU With 4x EHT-LTF And 0.8 us GI: 1" in eht
        assert "PPE Thresholds Present: 0" in eht
        assert "EHT-MCS 15 80 MHz: 0" in eht
        assert "EHT-MCS 15 160 MHz: 0" in eht
        assert "EHT-MCS 15 320 MHz: 0" in eht
        assert "EHT DUP In 6 GHz (MCS 14): 1" in eht
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 44 44 44" in eht
        assert "Supported EHT-MCS And NSS Set (160 MHz): 44 44 44" in eht
        assert "Supported EHT-MCS And NSS Set (320 MHz):" not in eht
        assert "MCS 0-9: Rx 4 SS, Tx 4 SS" in eht
        assert "MCS 10-11: Rx 4 SS, Tx 4 SS" in eht
        assert "MCS 12-13: Rx 4 SS, Tx 4 SS" in eht
        assert "PPE Thresholds:" not in eht.replace("PPE Thresholds Present: 0", "")
        assert "Max NSS: 4, 320 MHz: no, MCS 14: yes, MCS 15: no" in eht
        assert "Extension: (108) EHT Capabilities" in str(unifi)

        ml = _ie_text(unifi, "Extension: (107) Multi-Link")
        assert "Multi-Link Control: 0x01b0" in ml
        assert "Type: Basic" in ml
        assert "Presence: 0x01b0" in ml
        assert "Common Info Length: 13" in ml
        assert "MLD MAC Address: 94:2a:6f:42:e4:77" in ml
        assert "Link ID: 0" in ml
        assert "BSS Parameters Change Count: 117" in ml
        assert "EML Capabilities: 0x4001" in ml
        assert "EMLSR Support: 1" in ml
        assert "EMLMR Support: 0" in ml
        assert "MLD Capabilities And Operations: 0x0021" in ml
        assert "Max Simultaneous Links: 2 (raw 1)" in ml
        assert "Per-STA Profiles:" not in ml

        aruba = lswifi.elements.WirelessNetworkBss(BssRecord(**ARUBA))
        eht = _ie_text(aruba, "Extension: (108) EHT Capabilities")
        assert "OM Control: 1" in eht
        assert "Max MPDU Length: 11454" in eht
        assert "Max A-MPDU Length Exponent Extension: 1" in eht
        assert "EHT TRS: 0" in eht
        assert "TXOP Return Support: 0" in eht
        assert "242-tone RU In BW Wider Than 20 MHz: 1" in eht
        assert "NDP With 4x EHT-LTF And 3.2 us GI: 1" in eht
        assert "SU Beamformer: 1" in eht
        assert "SU Beamformee: 0" in eht
        assert "Sounding Dimensions <= 80 MHz: 4 SS" in eht
        assert "Sounding Dimensions 160 MHz: reserved" in eht
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 44 44 44" in eht
        assert "Supported EHT-MCS And NSS Set (160 MHz):" not in eht
        assert "MCS 0-9: Rx 4 SS, Tx 4 SS" in eht
        assert "Max NSS: 4, 320 MHz: no, MCS 14: no, MCS 15: no" in eht
        ml = _ie_text(aruba, "Extension: (107) Multi-Link")
        assert "MLD MAC Address: 98:8f:00:9c:c4:60" in ml
        assert "Link ID: 2" in ml
        assert "EML Capabilities: 0x4001" in ml
        assert "EMLSR Support: 1" in ml
        assert "MLD Capabilities And Operations: 0x0062" in ml
        assert "Max Simultaneous Links: 3 (raw 2)" in ml
        assert "TID-To-Link Mapping Negotiation: 3 (different link sets)" in ml

    def test_eht_mcs_nss_size_matches_kernel(self):
        groups = lswifi.elements.WirelessNetworkBss._eht_mcs_nss_groups

        def size(he_phy0, eht_phy0, from_ap):
            return sum(len(labels) for _name, labels in groups(he_phy0, eht_phy0, from_ap))

        assert size(0x02, 0x02, True) == 3
        assert groups(0x02, 0x02, True)[0][0] == "<= 80 MHz"
        assert size(0x04, 0x00, True) == 3
        assert size(0x08, 0x00, True) == 3
        assert [name for name, _labels in groups(0x0C, 0x00, True)] == [
            "<= 80 MHz",
            "160 MHz",
        ]
        assert size(0x0C, 0x02, True) == 9
        assert size(0x00, 0x02, True) == 3
        assert size(0x10, 0x00, True) == 3
        assert size(0x00, 0x00, True) == 3
        assert size(0x00, 0x00, False) == 4
        only20 = groups(0x00, 0x00, False)[0]
        assert only20[0] == "20 MHz only"
        assert only20[1] == ("MCS 0-7", "MCS 8-9", "MCS 10-11", "MCS 12-13")

        lines, nss = lswifi.elements.WirelessNetworkBss._format_supported_eht_mcs(
            bytes.fromhex("44332211"), 0, 0, False, False
        )
        assert lines[0] == "Supported EHT-MCS And NSS Set (20 MHz only): 44 33 22 11"
        assert "MCS 0-7: Rx 4 SS, Tx 4 SS" in lines[1]
        assert "MCS 8-9: Rx 3 SS, Tx 3 SS" in lines[2]
        assert "MCS 10-11: Rx 2 SS, Tx 2 SS" in lines[3]
        assert "MCS 12-13: Rx 1 SS, Tx 1 SS" in lines[4]
        assert nss == 4

    def test_eht_capabilities_width_forms_and_ppe(self):
        def he(phy0):
            return _ext(bytes([35, 0, 0, 0, 0, 0, 0, phy0]))

        def eht(phy0, phy5, tail):
            phy = bytearray(9)
            phy[0] = phy0
            phy[5] = phy5
            return _ext(bytes([108, 0x00, 0x00]) + bytes(phy) + tail)

        early = _bss_with_ies(
            b"early", he(0x02) + eht(0x02, 0x00, bytes.fromhex("444444444444"))
        )
        text = _ie_text(early, "Extension: (108) EHT Capabilities")
        assert "320 MHz In 6 GHz: 1" in text
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 44 44 44" in text
        assert "Supported EHT-MCS And NSS Set (320 MHz):" not in text
        assert "trailing (raw 44 44 44)" in text
        assert "Max NSS: 4, 320 MHz: yes, MCS 14: no, MCS 15: no" in text

        wide = _bss_with_ies(
            b"wide",
            he(0x0C) + eht(0x02, 0x00, bytes.fromhex("111111222222333333")),
        )
        text = _ie_text(wide, "Extension: (108) EHT Capabilities")
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 11 11 11" in text
        assert "Supported EHT-MCS And NSS Set (160 MHz): 22 22 22" in text
        assert "Supported EHT-MCS And NSS Set (320 MHz): 33 33 33" in text
        assert "MCS 0-9: Rx 3 SS, Tx 3 SS" in text
        assert "Max NSS: 3, 320 MHz: yes, MCS 14: no, MCS 15: no" in text

        twenty = _bss_with_ies(b"ap20", he(0x00) + eht(0x00, 0x00, bytes.fromhex("112200")))
        text = _ie_text(twenty, "Extension: (108) EHT Capabilities")
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 11 22 00" in text
        assert "MCS 0-9: Rx 1 SS, Tx 1 SS" in text
        assert "MCS 10-11: Rx 2 SS, Tx 2 SS" in text
        assert "MCS 12-13: not supported" in text
        assert "20 MHz only" not in text
        assert "MCS 0-7:" not in text

        ppe = _bss_with_ies(b"ppe", he(0x04) + eht(0x00, 0x08, bytes.fromhex("444444abcd")))
        text = _ie_text(ppe, "Extension: (108) EHT Capabilities")
        assert "PPE Thresholds Present: 1" in text
        assert "PPE Thresholds: AB CD" in text
        assert "MCS 0-9: Rx 4 SS, Tx 4 SS" in text
        assert "trailing" not in text

        missing_he = _bss_with_ies(b"nohe", eht(0x00, 0x00, bytes.fromhex("444444")))
        text = _ie_text(missing_he, "Extension: (108) EHT Capabilities")
        assert "Supported EHT-MCS And NSS Set: 44 44 44" in text
        assert "MCS 0-9:" not in text
        assert "MCS 0-7:" not in text
        assert "Max NSS: unknown, 320 MHz: no, MCS 14: no, MCS 15: no" in text

        eht_first = _bss_with_ies(
            b"order", eht(0x00, 0x00, bytes.fromhex("444444")) + he(0x04)
        )
        text = _ie_text(eht_first, "Extension: (108) EHT Capabilities")
        assert "Supported EHT-MCS And NSS Set (<= 80 MHz): 44 44 44" in text
        assert "Max NSS: 4, 320 MHz: no, MCS 14: no, MCS 15: no" in text

        short_mcs = _bss_with_ies(b"shortmcs", he(0x04) + eht(0x00, 0x00, bytes.fromhex("44")))
        text = _ie_text(short_mcs, "Extension: (108) EHT Capabilities")
        assert "truncated (raw 44)" in text
        assert "MCS 0-9:" not in text
        assert "Max NSS: unknown" in text

    def test_multi_link_optional_fields_and_other_types(self):
        basic = bytes.fromhex(
            "6b"
            "f007"  # type Basic, presence through extended MLD caps
            "12"
            "112233445566"
            "03"
            "09"
            "ac10"
            "0140"
            "2100"
            "07"
            "8100"
            "aabb"
        )
        # control is little-endian on the wire: f0 07 is 0x07f0
        assert basic[1:3] == bytes.fromhex("f007")
        text = _ie_text(_bss_with_ies(b"full", _ext(basic)), "Extension: (107) Multi-Link")
        assert "Type: Basic" in text
        assert "Presence: 0x07f0" in text
        assert "MLD MAC Address: 11:22:33:44:55:66" in text
        assert "Link ID: 3" in text
        assert "BSS Parameters Change Count: 9" in text
        assert "Medium Synchronization Delay: 0x10ac" in text
        assert "Duration: 172 (5504 us)" in text
        assert "OFDM ED Threshold: 0 (-72 dBm)" in text
        assert "Max Number Of TXOPs: 1" in text
        assert "EML Capabilities: 0x4001" in text
        assert "MLD Capabilities And Operations: 0x0021" in text
        assert "Max Simultaneous Links: 2 (raw 1)" in text
        assert "AP MLD ID: 7" in text
        assert "Extended MLD Capabilities And Operations: 0x0081" in text
        assert "Operation Parameter Update: 1" in text
        assert "Recommended Max Simultaneous Links: 1 (raw 0)" in text
        unspecified = "\n".join(
            lswifi.elements.WirelessNetworkBss._format_extended_mld_capabilities(0x001E)
        )
        assert (
            "Recommended Max Simultaneous Links: not specified (raw 15)" in unspecified
        )
        assert "BTM MLD Recommendation For Multiple APs: 1" in text
        assert "Per-STA Profiles: AA BB" in text
        assert "STA Control" not in text

        emlmr = bytes.fromhex("6b8000091122334455669200")
        text = _ie_text(_bss_with_ies(b"emlmr", _ext(emlmr)), "Extension: (107) Multi-Link")
        assert "EML Capabilities: 0x0092" in text
        assert "EMLSR Support: 0" in text
        assert "EMLMR Support: 1" in text
        assert "EML Padding Delay: 32 us" in text
        assert "EMLMR Transition Delay: 32 us" in text
        assert "EMLSR Transition Delay:" not in text

        short_common = bytes.fromhex("6b10000711223344556605")
        text = _ie_text(
            _bss_with_ies(b"shortci", _ext(short_common)),
            "Extension: (107) Multi-Link",
        )
        assert "MLD MAC Address: 11:22:33:44:55:66" in text
        assert "Link ID:" not in text
        assert "truncated" in text
        assert "Per-STA Profiles: 05" in text

        for body, type_name in (
            ("6b0100dead", "Probe Request"),
            ("6b0200dead", "Reconfiguration"),
            ("6b0300dead", "TDLS"),
            ("6b0400dead", "Priority Access"),
            ("6b0700aa", "Unknown (7)"),
        ):
            text = _ie_text(
                _bss_with_ies(b"oth", _ext(bytes.fromhex(body))),
                "Extension: (107) Multi-Link",
            )
            assert f"Type: {type_name}" in text
            assert "MLD MAC Address:" not in text
            assert "raw " in text

    @pytest.mark.parametrize(
        "ies",
        [
            bytes([255, 1, 107]),
            bytes([255, 1, 108]),
            bytes([255, 2, 107, 0xB0]),
            bytes([255, 4, 107, 0xB0, 0x01, 0x0D]),
            bytes([255, 6, 107, 0x10, 0x00, 0xFF, 0x11, 0x22]),
            bytes([255, 2, 108, 0x07]),
            bytes([255, 5, 108, 0x07, 0x00, 0xE0, 0x1F]),
            bytes([255, 3, 108, 0x82, 0x01]),
        ],
    )
    def test_truncated_multilink_and_eht_do_not_raise(self, ies):
        bss = _bss_with_ies(b"bad", ies + bytes([3, 1, 6]))
        text = str(bss)
        assert "Traceback" not in text
        assert 3 in [ie.eid for ie in bss.information_elements]
        assert "truncated" in text

    def test_wifi7_fixture_json_stays_one_document(self, tmp_path, capsys):
        records = [
            lswifi.elements.WirelessNetworkBss(BssRecord(**ARUBA)),
            lswifi.elements.WirelessNetworkBss(BssRecord(**UNIFI)),
        ]
        path = tmp_path / "out.json"
        args = parse(["--json", str(path)])
        scanner = app.lswifi()
        out, _rnr, length, bssids, names, json_out, new = scanner.parse_bss_list(
            Session(records), False, "", str(path), args
        )
        scanner.print_bss_list(
            out, length, "00:11:22:33:44:55", bssids, False, names, json_out, new, args
        )
        printed = json.loads(capsys.readouterr().out)
        assert printed == json_out
        document = json.loads(path.read_text())
        assert list(document) == ["lswifi", "scan_data"]
        assert document["scan_data"] == json_out
        assert len(document["scan_data"]) == 2
        for row in document["scan_data"]:
            assert set(row) == JSON_KEYS
            assert isinstance(row["ies_extension"], list)
            assert all(isinstance(item, str) for item in row["ies_extension"])
            assert "107" in row["ies_extension"]
            assert "108" in row["ies_extension"]
