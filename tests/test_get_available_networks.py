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

if WLAN_API.WLAN_API_EXISTS:
    interfaces = WLAN_API.WLAN.get_wireless_interfaces()
    print(interfaces)
    for interface in interfaces:
        WLAN_API.WLAN.scan(interface.guid)
        time.sleep(0.1)
        available_networks = WLAN_API.WLAN.get_wireless_network_bss_list(interface)
        is_first_avail = True
        output = []
        for avail in available_networks:
            if is_first_avail:
                output.append([str(i).upper() for i in list(avail.__dict__.keys())])
                is_first_avail = False
            output.append([str(i) for i in list(avail.__dict__.values())])

        print(available_networks)
        assert len(available_networks) > 0
