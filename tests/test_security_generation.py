import pytest

import lswifi.elements
from lswifi.backends.base import BssRecord

WPA_IE = bytes.fromhex("dd160050f20101000050f20201000050f20201000050f202")


def _bss(ie_bytes, capability=0x0011):
    ssid = b"test-net"
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


def _rsn(akms, pairwise=(4,), group=4, caps=0x0000, akm_oui=b"\x00\x0f\xac"):
    body = b"\x01\x00"
    body += b"\x00\x0f\xac" + bytes([group])
    body += len(pairwise).to_bytes(2, "little")
    for p in pairwise:
        body += b"\x00\x0f\xac" + bytes([p])
    body += len(akms).to_bytes(2, "little")
    for a in akms:
        body += akm_oui + bytes([a])
    body += caps.to_bytes(2, "little")
    return bytes([48, len(body)]) + body


@pytest.mark.parametrize(
    "ie_bytes,capability,expected",
    [
        (_rsn([8], caps=0x00C0), 0x0011, "WPA3"),
        (_rsn([2, 8], caps=0x0080), 0x0011, "WPA2/WPA3"),
        (_rsn([24], caps=0x00C0), 0x0011, "WPA3"),
        (_rsn([5], caps=0x00C0), 0x0011, "WPA3"),
        (_rsn([1, 5], caps=0x0080), 0x0011, "WPA2/WPA3"),
        (_rsn([1]), 0x0011, "WPA2"),
        (_rsn([5]), 0x0011, "WPA2"),
        (_rsn([12], pairwise=(9,), group=9, caps=0x00C0), 0x0011, "WPA3-192"),
        (_rsn([12], pairwise=(4,), group=4), 0x0011, "WPA2"),
        (_rsn([18]), 0x0011, "OWE"),
        (WPA_IE, 0x0011, "WPA"),
        (WPA_IE + _rsn([2]), 0x0011, "WPA/WPA2"),
        (b"", 0x0011, "WEP"),
        (b"", 0x0001, "Open"),
        (_rsn([2], akm_oui=b"\x50\x6f\x9a"), 0x0011, "WPA2"),
        (_rsn([9]), 0x0011, "WPA3"),
        (_rsn([4, 9], caps=0x0080), 0x0011, "WPA2/WPA3"),
    ],
    ids=[
        "sae_mfpr",
        "psk_sae_mfpc",
        "sae_gdh_only",
        "dot1x_sha256_mfpc_mfpr",
        "akm1_and_dot1x_mfpc",
        "akm1_only",
        "dot1x_no_mfpc",
        "suite_b_192_gcmp256_mfpr",
        "suite_b_ccmp128",
        "owe_only",
        "wpa_ie_only",
        "wpa_ie_plus_rsn_psk",
        "nothing_privacy",
        "nothing_open",
        "non_ac_oui_akm",
        "ft_sae",
        "ft_psk_ft_sae_mfpc",
    ],
)
def test_security_generation(ie_bytes, capability, expected):
    bss = _bss(ie_bytes, capability)
    assert str(bss.security_generation) == expected
