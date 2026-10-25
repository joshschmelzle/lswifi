# -*- encoding: utf-8

import csv

import pytest

from lswifi import app
from lswifi.backends.base import BssRecord
from lswifi.elements import WirelessNetworkBss
from lswifi.schemas.phy import PHYType
from tests.test_backends import Session, parse


class TestPHYType:
    """Test PHYType with the PHY names a backend can report."""

    def test_phy_eht(self):
        phy = PHYType("EHT")
        assert phy.amendment == "be"
        assert phy.generation == "7"
        assert str(phy) == "be"
        assert phy.name == "EHT"
        assert repr(phy) == "EHT"

    def test_phy_he(self):
        phy = PHYType("HE")
        assert phy.amendment == "ax"
        assert phy.generation == "6"

    def test_phy_vht(self):
        phy = PHYType("VHT")
        assert phy.amendment == "ac"
        assert phy.generation == "5"

    def test_phy_ht(self):
        phy = PHYType("HT")
        assert phy.amendment == "n"
        assert phy.generation == "4"

    def test_phy_erp(self):
        phy = PHYType("ERP")
        assert phy.amendment == "g"
        assert phy.generation == "3"

    def test_phy_hrdsss(self):
        phy = PHYType("HR-DSSS")
        assert phy.amendment == "b"
        assert phy.generation == "2"

    def test_phy_ofdm(self):
        phy = PHYType("OFDM")
        assert phy.amendment == "a"
        assert phy.generation == "1"

    def test_phy_unknown(self):
        phy = PHYType("UNKNOWN")
        assert phy.amendment == ""
        assert phy.generation == "-"

    def test_phy_windows_dict_value(self):
        """Windows DOT11_PHY_TYPE_DICT values keep today's blank amendment."""
        phy = PHYType("HT (802.11n)")
        assert phy.name == "HT (802.11n)"
        assert phy.amendment == ""

    def test_phy_none(self):
        """A backend without a PHY enum leaves the column blank."""
        phy = PHYType(None)
        assert phy.name == ""
        assert phy.amendment == ""
        assert phy.generation == "-"
        assert str(phy.out()) == ""

    def test_phy_out(self):
        phy = PHYType("HE")
        result = phy.out()
        assert str(result) == "ax"

    def test_phy_name_setter(self):
        phy = PHYType("HE")
        phy.name = "VHT"
        assert phy.name == "VHT"
        assert phy.amendment == "ac"

    def test_promote_keeps_the_higher_phy(self):
        phy = PHYType(None)
        phy.promote("HT")
        phy.promote("ERP")
        assert phy.name == "HT"
        phy.promote("EHT")
        phy.promote("HE")
        assert phy.name == "EHT"
        assert phy.amendment == "be"


def _tlv(eid, body):
    body = bytes(body)
    return bytes((eid, len(body))) + body


# 1, 2, 5.5, 11 Mbps, basic
_B_RATES = bytes.fromhex("82848b96")
# those plus 6, 9, 12, 18
_BG_RATES = bytes.fromhex("82848b960c121824")
# 24, 36, 48, 54
_G_EXT_RATES = bytes.fromhex("3048606c")
# 6(B), 9, 12(B), 18, 24(B), 36, 48, 54
_A_RATES = bytes.fromhex("8c129824b048606c")
# HT Capabilities: 40 MHz, MCS 0-15
_HT_CAP = bytes.fromhex("6e0017ffff") + bytes(21)
# HT Operation: primary channel, secondary above, STA channel width 40 MHz
_HT_OP_CH1 = bytes((1, 0x05)) + bytes(20)
_HT_OP_CH36 = bytes((36, 0x05)) + bytes(20)
# VHT Capabilities (12) and VHT Operation: 80 MHz, center 42
_VHT_CAP = bytes.fromhex("b2018033faff0000faff0000")
_VHT_OP = bytes.fromhex("012a00fcff")
# WPA vendor IE, PSK/TKIP
_WPA_TKIP = bytes.fromhex("dd160050f20101000050f20201000050f20201000050f202")


def _he_capabilities():
    body = bytearray(22)
    body[0] = 35
    body[18] = 0xFF
    body[19] = 0xFF
    return bytes(body)


def _ht_24():
    return b"".join(
        (
            _tlv(0, b"ht"),
            _tlv(1, _BG_RATES),
            _tlv(3, b"\x01"),
            _tlv(42, b"\x00"),
            _tlv(50, _G_EXT_RATES),
            _tlv(45, _HT_CAP),
            _tlv(61, _HT_OP_CH1),
        )
    )


def _erp():
    return b"".join(
        (
            _tlv(0, b"erp"),
            _tlv(1, _BG_RATES),
            _tlv(3, b"\x06"),
            _tlv(42, b"\x00"),
            _tlv(50, _G_EXT_RATES),
            _WPA_TKIP,
        )
    )


def _erp_from_rates():
    return b"".join(
        (
            _tlv(0, b"g"),
            _tlv(1, _BG_RATES),
            _tlv(3, b"\x06"),
            _tlv(50, _G_EXT_RATES),
        )
    )


def _erp_element_only():
    return b"".join(
        (
            _tlv(0, b"erp"),
            _tlv(1, _B_RATES),
            _tlv(3, b"\x01"),
            _tlv(42, b"\x01"),
        )
    )


def _dsss():
    return b"".join(
        (
            _tlv(0, b"wep"),
            _tlv(1, _B_RATES),
            _tlv(3, b"\x01"),
        )
    )


def _vht_5():
    return b"".join(
        (
            _tlv(0, b"vht"),
            _tlv(1, _A_RATES),
            _tlv(45, _HT_CAP),
            _tlv(61, _HT_OP_CH36),
            _tlv(191, _VHT_CAP),
            _tlv(192, _VHT_OP),
        )
    )


def _ht_24_with_vht_ies():
    return _ht_24() + _tlv(191, _VHT_CAP) + _tlv(192, bytes.fromhex("000000fcff"))


def _ofdm_5():
    return b"".join(
        (
            _tlv(0, b"ofdm"),
            _tlv(1, _A_RATES),
            _tlv(7, b"US \x24\x04\x17"),
        )
    )


def _he_and_ht():
    return _ht_24() + _tlv(255, _he_capabilities())


def _exported(record, tmp_path):
    bss = WirelessNetworkBss(record)
    json_path = tmp_path / "out.json"
    csv_path = tmp_path / "out.csv"
    args = parse(["-all", "--json", str(json_path), "--csv", str(csv_path)])
    out, _rnr, _length, _bssids, _names, json_out, _new = app.lswifi().parse_bss_list(
        Session([bss]), False, str(csv_path), str(json_path), args
    )
    table = next(cell.value for cell in out[0] if str(cell.header) == "PHY")
    with csv_path.open(newline="") as handle:
        csv_phy = next(csv.DictReader(handle))["phy_type"]
    return bss, table, json_out[0]["phy_type"], csv_phy


class TestPhyFromIes:
    """macOS and Linux pass no PHY name. Derive it from the IEs."""

    @pytest.mark.parametrize(
        "ies, mhz, phy_name, name, column",
        [
            pytest.param(_ht_24(), 2412, None, "HT", "n", id="ht-24"),
            pytest.param(_erp(), 2437, None, "ERP", "g", id="erp"),
            pytest.param(
                _erp_from_rates(), 2437, None, "ERP", "g", id="erp-ofdm-rates"
            ),
            pytest.param(_erp_element_only(), 2412, None, "ERP", "g", id="erp-element"),
            pytest.param(_dsss(), 2412, None, "HR-DSSS", "b", id="dsss"),
            pytest.param(_vht_5(), 5180, None, "VHT", "ac", id="vht-5"),
            pytest.param(
                _ht_24_with_vht_ies(), 2412, None, "HT", "n", id="vht-ies-on-24"
            ),
            pytest.param(_ofdm_5(), 5180, None, "OFDM", "a", id="ofdm-5"),
            pytest.param(_he_and_ht(), 2412, None, "HE", "ax", id="he-not-downgraded"),
            pytest.param(
                _ht_24(),
                2412,
                "HT (802.11n)",
                "HT (802.11n)",
                "",
                id="windows-untouched",
            ),
        ],
    )
    def test_phy_column_json_and_csv(self, tmp_path, ies, mhz, phy_name, name, column):
        record = BssRecord(
            ssid=b"legacy",
            bssid="02:00:00:00:00:10",
            frequency_mhz=mhz,
            rssi_dbm=-40,
            capability=0x0011,
            ies=ies,
            phy_name=phy_name,
        )
        bss, table, json_phy, csv_phy = _exported(record, tmp_path)
        assert bss.phy_type.name == name
        assert table == column
        assert json_phy == column
        assert csv_phy == column
        assert str(bss.phy_type) == column
