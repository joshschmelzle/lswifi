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
lswifi.updatecheck
~~~~~~~~~~~~~~~~~~

Tell the user when PyPI has a newer lswifi, asking PyPI at most once a day.
"""

import json
import logging
import os
import re
import ssl
import time
import urllib.request
from collections.abc import Callable

from lswifi.__version__ import __title__, __version__
from lswifi.helpers import app_data_dir, write_json

log = logging.getLogger(__name__)

PYPI_URL = f"https://pypi.org/pypi/{__title__}/json"
CHECK_INTERVAL_S = 24 * 60 * 60
TIMEOUT_S = 2.0
STATE_FILE = "update-check.json"
DISABLE_ENV = "LSWIFI_NO_UPDATE_CHECK"
SYSTEM_CA_BUNDLE = "/etc/ssl/cert.pem"


def disabled(args) -> bool:
    if getattr(args, "no_update_check", False):
        return True
    return os.environ.get(DISABLE_ENV, "").strip().lower() not in ("", "0", "false")


def parse_version(text: str) -> tuple[int, ...] | None:
    """Release versions only: 0.6.0 parses, 0.6.0rc1 does not"""
    if not re.fullmatch(r"\d+(\.\d+)*", text or ""):
        return None
    return tuple(int(part) for part in text.split("."))


def is_newer(latest: str, installed: str) -> bool:
    new, old = parse_version(latest), parse_version(installed)
    return new is not None and old is not None and new > old


def tls_context(system_bundle: str = SYSTEM_CA_BUNDLE) -> ssl.SSLContext:
    """The python.org macOS Python has no CA certificates until its Install
    Certificates step is run; fall back to the bundle macOS ships"""
    context = ssl.create_default_context()
    if not context.cert_store_stats()["x509_ca"] and os.path.isfile(system_bundle):
        context.load_verify_locations(cafile=system_bundle)
    return context


def fetch_latest() -> str:
    request = urllib.request.Request(
        PYPI_URL, headers={"User-Agent": f"{__title__}/{__version__}"}
    )
    with urllib.request.urlopen(
        request, timeout=TIMEOUT_S, context=tls_context()
    ) as response:
        return str(json.load(response)["info"]["version"])


def latest_version(
    now: float,
    state_path: str,
    fetch: Callable[[], str] | None = None,
) -> str | None:
    """The latest version on PyPI, asking PyPI only when the last attempt is
    a day old. A failed attempt counts too, so lswifi offline doesn't wait on
    the network every run."""
    try:
        with open(state_path) as file:
            state = json.load(file)
        if 0 <= now - float(state["checked"]) < CHECK_INTERVAL_S:
            return state.get("latest")
    except (OSError, ValueError, KeyError, TypeError):
        pass
    latest = None
    try:
        latest = (fetch or fetch_latest)()
    except Exception as error:
        log.debug("update check failed: %s", error)
    state = {"checked": now}
    if latest:
        state["latest"] = latest
    try:
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        write_json(state_path, state, None)
    except OSError as error:
        log.debug("could not save the update check time: %s", error)
    return latest


def notify(args, now: Callable[[], float] = time.time) -> None:
    if disabled(args):
        return
    try:
        state_path = os.path.join(app_data_dir(), STATE_FILE)
    except OSError:
        return
    latest = latest_version(now(), state_path)
    if latest and is_newer(latest, __version__):
        log.info(
            "lswifi %s is available (you have %s); upgrade with: "
            "python -m pip install --upgrade lswifi. "
            "Turn this check off with --no-update-check or %s=1",
            latest,
            __version__,
            DISABLE_ENV,
        )
