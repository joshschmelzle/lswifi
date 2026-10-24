#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

"""
lswifi.backends.factory
~~~~~~~~~~~~~~~~~~~~~~~

pick a Wi-Fi backend from sys.platform
"""

import sys

from lswifi.backends.base import BackendNotImplementedError, WifiBackend

_NOT_IMPLEMENTED: dict[str, str] = {}


def backend_name_for_platform(platform: str | None = None) -> str | None:
    """Return the backend name for a sys.platform value, or None"""
    platform = sys.platform if platform is None else platform
    if platform == "win32":
        return "windows"
    if platform.startswith("linux"):
        return "linux"
    if platform == "darwin":
        return "darwin"
    return None


def get_backend(platform: str | None = None) -> WifiBackend:
    """Return the Wi-Fi backend for this platform.

    Raises BackendNotImplementedError where no backend exists yet, and
    BackendUnavailableError if the platform library cannot be loaded.
    """
    platform = sys.platform if platform is None else platform
    name = backend_name_for_platform(platform)
    if name == "windows":
        from lswifi.backends.windows import WindowsBackend

        return WindowsBackend()
    if name == "darwin":
        from lswifi.backends.macos import MacOSBackend

        return MacOSBackend()
    if name == "linux":
        from lswifi.backends.linux import LinuxBackend

        return LinuxBackend()
    if name in _NOT_IMPLEMENTED:
        raise BackendNotImplementedError(
            f"scanning is not implemented yet on {_NOT_IMPLEMENTED[name]}. "
            "lswifi currently scans on Windows, macOS, and Linux. "
            "Commands that do not scan still work here: -decode <pcap>, "
            "-decoderaw <file.ies>, --help, and --version."
        )
    raise BackendNotImplementedError(
        f"no Wi-Fi backend for platform {platform!r}. "
        "lswifi currently scans on Windows, macOS, and Linux."
    )


def needs_backend(args) -> bool:
    """Whether the parsed command line needs a Wi-Fi backend.

    Decoding a capture or a raw IE file works without a local adapter.
    """
    return not (
        getattr(args, "decode", None)
        or getattr(args, "decoderaw", None)
        or getattr(args, "data_location", False)
        or getattr(args, "command", None) == "completion"
    )
