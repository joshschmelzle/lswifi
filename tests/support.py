import pytest


def wireless_interfaces(wlanapi):
    """Return wireless interfaces, or skip when the WLAN service is unavailable.

    Hosted Windows runners load wlanapi.dll, but WLAN AutoConfig is often
    stopped, so WlanOpenHandle fails before a scan can start.
    """
    try:
        return wlanapi.WLAN.get_wireless_interfaces()
    except Exception as exc:
        pytest.skip(f"WLAN service unavailable: {exc}")
