# -*- encoding: utf-8
"""
Tests for querying current connection info from WLAN API.

Note: The benchmark functionality from the original script is preserved
in the if __name__ == "__main__" block for manual testing.
"""

import sys

import pytest

from lswifi import wlanapi as WLAN_API


@pytest.mark.skipif(not WLAN_API.WLAN_API_EXISTS, reason="WLAN API not available")
class TestCurrentConnectionInfo:
    """Tests for current connection info queries."""

    def test_query_interface_returns_tuple(self):
        """Test that query_interface returns expected format."""
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        if not interfaces:
            pytest.skip("No wireless interfaces available")

        for _idx, interface in interfaces.items():
            try:
                result = WLAN_API.WLAN.query_interface(
                    interface, "current_connection"
                )
                # Result should be a tuple or have indexable structure
                assert result is not None
            except Exception:
                # May fail if not connected - that's OK
                pytest.skip("Not connected to a network")


# Benchmark script preserved for manual testing
if __name__ == "__main__":
    import ast
    import timeit

    def func_a(verbose):
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        for _idx, interface in interfaces.items():
            result_tuple = WLAN_API.WLAN.query_interface(
                interface, "current_connection"
            )
            out = ast.literal_eval((str(result_tuple).split(",", 1)[1][:-1].strip()))
            if verbose:
                print("func_a() x 1:")
                print(f"    {out}")
                print(f"    bssid: {out['wlanAssociationAttributes']['dot11Bssid']}")

    def func_b(verbose):
        interfaces = WLAN_API.WLAN.get_wireless_interfaces()
        for _idx, interface in interfaces.items():
            result_tuple = WLAN_API.WLAN.query_interface(
                interface, "current_connection"
            )
            out = result_tuple[1]["wlanAssociationAttributes"]["dot11Bssid"]
            if verbose:
                print("func_b() x 1:")
                print(f"    {result_tuple[1]}")
                print(f"    {out}")

    print("This script uses WLAN_ASSOCIATION_ATTRIBUTES which does not include RSSI.")
    func_a(True)
    func_b(True)

    for func_name, func in [("func_a", func_a), ("func_b", func_b)]:
        for n in [10, 100, 1000, 10000]:
            setup = f"from __main__ import {func_name}"
            t = timeit.timeit(f"{func_name}(False)", setup=setup, number=n)
            print(f"{func_name}() x {n}:\n    {t} seconds")
