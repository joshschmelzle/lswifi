# -*- encoding: utf-8

import time

import pytest

from lswifi import wlanapi as WLAN_API


def dequote(s):
    """
    If a string has single or double quotes around it, remove them.
    Make sure the pair of quotes match.
    If a matching pair of quotes is not found, return the string unchanged.
    """
    if (s[0] == s[-1]) and s.startswith(("'", '"')):
        return s[1:-1]
    return s


class TestDequote:
    def test_dequote_single_quotes(self):
        assert dequote("'hello'") == "hello"

    def test_dequote_double_quotes(self):
        assert dequote('"hello"') == "hello"

    def test_dequote_no_quotes(self):
        assert dequote("hello") == "hello"

    def test_dequote_mismatched_quotes(self):
        assert dequote("'hello\"") == "'hello\""


@pytest.mark.skipif(not WLAN_API.WLAN_API_EXISTS, reason="WLAN API not available")
class TestGetAvailableNetworks:
    def test_get_wireless_interfaces(self):
        """Test that we can get wireless interfaces."""
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        assert isinstance(interfaces, dict)

    def test_scan_and_get_bss_list(self):
        """Test scanning and getting BSS list from available interfaces."""
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        if not interfaces:
            pytest.skip("No wireless interfaces available")

        for _idx, interface in interfaces.items():
            WLAN_API.WLAN.scan(interface.guid)
            time.sleep(0.1)
            available_networks = WLAN_API.WLAN.get_wireless_network_bss_list(
                interface, is_bytes_arg=False
            )
            # Networks list should be iterable (may be empty if no APs nearby)
            assert hasattr(available_networks, "__iter__")
