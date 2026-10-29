import pytest

import lswifi.elements
from lswifi.backends.base import BssRecord

WPA_IE = bytes.fromhex("dd160050f20101000050f20201000050f20201000050f202")


def _bss(ie_bytes, capability=0x0011, frequency_mhz=2437):
    ssid = b"test-net"
    ies = bytes([0, len(ssid)]) + ssid + bytes([1, 1, 0x82]) + ie_bytes
    return lswifi.elements.WirelessNetworkBss(
        BssRecord(
            ssid=ssid,
            bssid="02:00:00:00:00:10",
            frequency_mhz=frequency_mhz,
            capability=capability,
            ies=ies,
        )
    )


def _rsn(
    akms, pairwise=(4,), group=4, caps=0x0000, akm_oui=b"\x00\x0f\xac", group_mgmt=None
):
    body = b"\x01\x00"
    body += b"\x00\x0f\xac" + bytes([group])
    body += len(pairwise).to_bytes(2, "little")
    for p in pairwise:
        body += b"\x00\x0f\xac" + bytes([p])
    body += len(akms).to_bytes(2, "little")
    for a in akms:
        body += akm_oui + bytes([a])
    body += caps.to_bytes(2, "little")
    if group_mgmt is not None:
        body += b"\x00\x00" + b"\x00\x0f\xac" + bytes([group_mgmt])
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
        (
            _rsn([12], pairwise=(9,), group=9, caps=0x00C0, group_mgmt=12),
            0x0011,
            "WPA3-192",
        ),
        (_rsn([12], pairwise=(4,), group=4), 0x0011, "WPA2"),
        (_rsn([18]), 0x0011, "OWE"),
        (WPA_IE, 0x0011, "WPA"),
        (WPA_IE + _rsn([2]), 0x0011, "WPA/WPA2"),
        (b"", 0x0011, "WEP"),
        (b"", 0x0001, "Open"),
        (_rsn([2], akm_oui=b"\x50\x6f\x9a"), 0x0011, "WPA2"),
        (_rsn([9], caps=0x00C0), 0x0011, "WPA3"),
        (_rsn([4, 9], caps=0x0080), 0x0011, "WPA2/WPA3"),
        (_rsn([12], pairwise=(9,), group=9, caps=0x00C0), 0x0011, "WPA3"),
        (
            _rsn([12], pairwise=(9,), group=9, caps=0x00C0, group_mgmt=11),
            0x0011,
            "WPA3",
        ),
        (
            _rsn([12], pairwise=(9, 4), group=9, caps=0x00C0, group_mgmt=12),
            0x0011,
            "WPA3",
        ),
        (
            _rsn([12, 5], pairwise=(9,), group=9, caps=0x00C0, group_mgmt=12),
            0x0011,
            "WPA3",
        ),
        (
            _rsn([13], pairwise=(9,), group=9, caps=0x00C0, group_mgmt=12),
            0x0011,
            "WPA3",
        ),
        (
            _rsn([12], pairwise=(9,), group=9, caps=0x0080, group_mgmt=12),
            0x0011,
            "WPA3",
        ),
        (_rsn([1], caps=0x00C0), 0x0011, "WPA2"),
        (_rsn([3], caps=0x00C0), 0x0011, "WPA3"),
        (_rsn([3], caps=0x0080), 0x0011, "WPA2/WPA3"),
        (_rsn([3]), 0x0011, "WPA2"),
        (_rsn([5], caps=0x0080), 0x0011, "WPA2/WPA3"),
        (_rsn([2, 6], caps=0x00C0), 0x0011, "WPA2"),
        (_rsn([8]), 0x0011, "SAE"),
        (_rsn([2, 8]), 0x0011, "WPA2"),
        (_rsn([9]), 0x0011, "SAE"),
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
        "suite_b_192_default_group_mgmt",
        "suite_b_192_bip_gmac128",
        "suite_b_192_extra_pairwise",
        "suite_b_192_extra_akm",
        "ft_dot1x_sha384_mfpr",
        "suite_b_192_mfpc_only",
        "akm1_only_mfpr",
        "ft_dot1x_mfpr",
        "ft_dot1x_mfpc",
        "ft_dot1x_no_mfpc",
        "dot1x_sha256_mfpc",
        "psk_sha256_mfpr",
        "sae_no_pmf",
        "psk_sae_no_pmf",
        "ft_sae_no_pmf",
    ],
)
def test_security_generation(ie_bytes, capability, expected):
    bss = _bss(ie_bytes, capability)
    assert str(bss.security_generation) == expected


@pytest.mark.parametrize(
    "ie_bytes,capability,frequency_mhz,expected",
    [
        (b"", 0x0011, 5975, ["6ghz-wep"]),
        (b"", 0x0001, 5975, ["6ghz-open"]),
        (WPA_IE + _rsn([8], caps=0x00C0), 0x0011, 5975, ["6ghz-wpa"]),
        (_rsn([8], pairwise=(2,), caps=0x00C0), 0x0011, 5975, ["6ghz-tkip"]),
        (_rsn([8], group=2, caps=0x00C0), 0x0011, 5975, ["6ghz-tkip"]),
        (_rsn([2, 8], caps=0x00C0), 0x0011, 5975, ["6ghz-psk"]),
        (_rsn([1, 5], caps=0x00C0), 0x0011, 5975, ["6ghz-dot1x-sha1"]),
        (_rsn([8], caps=0x0080), 0x0011, 5975, ["6ghz-pmf-not-required"]),
        (
            _rsn([2, 8], caps=0x0080),
            0x0011,
            5975,
            ["6ghz-psk", "6ghz-pmf-not-required"],
        ),
        (_rsn([8], caps=0x00C0), 0x0011, 5975, []),
        (_rsn([18], caps=0x00C0), 0x0011, 5975, []),
        (_rsn([2]), 0x0011, 5180, []),
        (b"", 0x0001, 2437, []),
    ],
    ids=[
        "six_ghz_wep",
        "six_ghz_open",
        "six_ghz_wpa_element",
        "six_ghz_tkip_pairwise",
        "six_ghz_tkip_group",
        "six_ghz_psk",
        "six_ghz_dot1x_sha1",
        "six_ghz_pmf_capable",
        "six_ghz_psk_and_pmf_capable",
        "six_ghz_sae_pmf_required",
        "six_ghz_owe_pmf_required",
        "five_ghz_psk",
        "two_four_ghz_open",
    ],
)
def test_six_ghz_nonconformant(ie_bytes, capability, frequency_mhz, expected):
    bss = _bss(ie_bytes, capability, frequency_mhz)
    assert bss.security_generation.nonconformant == expected


def test_six_ghz_marker_leaves_label_unchanged():
    bss = _bss(_rsn([2, 8], caps=0x0080), frequency_mhz=5975)
    assert str(bss.security_generation) == "WPA2/WPA3"
    assert bss.security_generation.out().value == "WPA2/WPA3!"


def test_five_ghz_cell_has_no_marker():
    bss = _bss(_rsn([2]), frequency_mhz=5180)
    assert bss.security_generation.out().value == "WPA2"
