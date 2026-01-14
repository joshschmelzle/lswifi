# -*- encoding: utf-8

import pytest

from lswifi import wlanapi as WLAN_API


class TestWlanApiConstants:
    """Test WLAN API constants and dictionaries."""

    def test_wlan_api_exists_is_bool(self):
        assert isinstance(WLAN_API.WLAN_API_EXISTS, bool)

    def test_dot11_phy_type_dict(self):
        """Test that PHY type dictionary has expected entries."""
        values = list(WLAN_API.DOT11_PHY_TYPE_DICT.values())
        # Check that Wi-Fi generations are represented
        assert any("HE" in v for v in values)  # Wi-Fi 6
        assert any("VHT" in v for v in values)  # Wi-Fi 5
        assert any("HT" in v for v in values)  # Wi-Fi 4

    def test_dot11_bss_type_dict(self):
        """Test BSS type dictionary."""
        assert "Infrastructure" in WLAN_API.DOT11_BSS_TYPE_DICT.values()

    def test_dot11_auth_algorithm_dict(self):
        """Test auth algorithm dictionary."""
        assert "Open" in WLAN_API.DOT11_AUTH_ALGORITHM_DICT.values()

    def test_dot11_cipher_algorithm_dict(self):
        """Test cipher algorithm dictionary."""
        assert "CCMP" in WLAN_API.DOT11_CIPHER_ALGORITHM_DICT.values()


@pytest.mark.skipif(not WLAN_API.WLAN_API_EXISTS, reason="WLAN API not available")
class TestWlanApiLive:
    """Tests that require actual WLAN API (Windows with Wi-Fi)."""

    def test_wlan_class_exists(self):
        """Test that WLAN class is available."""
        assert hasattr(WLAN_API, "WLAN")

    def test_get_wireless_interfaces(self):
        """Test getting wireless interfaces."""
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        assert isinstance(interfaces, dict)
