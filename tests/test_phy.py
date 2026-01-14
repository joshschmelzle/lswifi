# -*- encoding: utf-8

import pytest
from unittest.mock import MagicMock, patch

from lswifi.schemas.phy import PHYType


class TestPHYType:
    """Test PHYType class by mocking WLAN_API."""

    @pytest.fixture
    def mock_bss_entry(self):
        """Create a mock BSS entry."""
        entry = MagicMock()
        entry.dot11BssPhyType = 7  # arbitrary value
        return entry

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_eht(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "EHT"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "be"
        assert phy.generation == "7"
        assert str(phy) == "be"
        assert phy.name == "EHT"
        assert repr(phy) == "EHT"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_he(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "HE"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "ax"
        assert phy.generation == "6"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_vht(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "VHT"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "ac"
        assert phy.generation == "5"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_ht(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "HT"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "n"
        assert phy.generation == "4"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_erp(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "ERP"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "g"
        assert phy.generation == "3"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_hrdsss(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "HR-DSSS"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "b"
        assert phy.generation == "2"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_ofdm(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "OFDM"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == "a"
        assert phy.generation == "1"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_unknown(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "UNKNOWN"}
        phy = PHYType(mock_bss_entry)
        assert phy.amendment == ""
        assert phy.generation == "-"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_out(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "HE"}
        phy = PHYType(mock_bss_entry)
        result = phy.out()
        assert str(result) == "ax"

    @patch("lswifi.schemas.phy.WLAN_API")
    def test_phy_name_setter(self, mock_wlan, mock_bss_entry):
        mock_wlan.DOT11_PHY_TYPE_DICT = {7: "HE"}
        phy = PHYType(mock_bss_entry)
        phy.name = "VHT"
        assert phy.name == "VHT"
        assert phy.amendment == "ac"
