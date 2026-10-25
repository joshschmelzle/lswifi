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
lswifi.backends.macos_location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Location Services for the macOS backend.

CoreWLAN hides SSID, BSSID, and information elements until this process has a
Location Services grant. CoreLocation only presents the prompt if this thread's
run loop is running; sleeping leaves the status not determined. CoreLocation
is imported lazily so this module imports on any OS.
"""

import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# CLAuthorizationStatus. 3 and 4 are both a grant on macOS.
CL_NOT_DETERMINED = 0
CL_RESTRICTED = 1
CL_DENIED = 2
CL_AUTHORIZED_ALWAYS = 3
CL_AUTHORIZED_WHEN_IN_USE = 4
_GRANTED = (CL_AUTHORIZED_ALWAYS, CL_AUTHORIZED_WHEN_IN_USE)

AUTHORIZED = "authorized"
DENIED = "denied"
RESTRICTED = "restricted"
NOT_DETERMINED = "not_determined"
NOT_REGISTERED = "not_registered"
DISABLED = "disabled"
UNAVAILABLE = "unavailable"

# Long enough for a person to answer the prompt. Shorter when nobody is there.
WAIT_INTERACTIVE_S = 15.0
WAIT_HEADLESS_S = 1.0
# An ad-hoc interpreter never gets the prompt; don't burn the long wait on it.
UNSIGNED_WAIT_S = 0.5
POLL_S = 0.25

_SETTINGS = "System Settings > Privacy & Security > Location Services"
_HIDE = (
    "macOS hides SSID, BSSID, and information elements (security, width, amendments)"
)
_PYTHON_ORG = "https://www.python.org/downloads/macos/"
SIGNED_PYTHON_HELP = (
    "lswifi needs a code-signed Python (for example, the python.org "
    f"installer: {_PYTHON_ORG}). "
    "Unsigned interpreters such as uv, Homebrew, and pyenv builds "
    "cannot be granted. "
    f"Enable Python in {_SETTINGS}."
)

DENIED_MESSAGE = (
    f"{_HIDE} because Location Services is denied for this Python; "
    f"showing RSSI and channel only. {SIGNED_PYTHON_HELP}"
)
RESTRICTED_MESSAGE = (
    f"{_HIDE} because Location Services is restricted for this process; "
    "showing RSSI and channel only. Parental controls or device management "
    "have to allow it."
)
NOT_DETERMINED_MESSAGE = (
    f"{_HIDE} because Location Services is not determined for this "
    "Python; showing RSSI and channel only. lswifi asked for access. "
    f"{SIGNED_PYTHON_HELP}"
)
NOT_REGISTERED_MESSAGE = (
    f"{_HIDE} because this Python is not code-signed; "
    f"showing RSSI and channel only. {SIGNED_PYTHON_HELP}"
)
DISABLED_MESSAGE = (
    f"{_HIDE} because Location Services is turned off; showing RSSI and "
    f"channel only. Turn it on in {_SETTINGS}, then enable Python."
)
GENERIC_MESSAGE = (
    f"{_HIDE} until this Python has a Location Services grant; "
    f"showing RSSI and channel only. {SIGNED_PYTHON_HELP}"
)
CORELOCATION_MISSING = (
    f"{_HIDE} because CoreLocation is not available to this Python, so "
    "lswifi cannot request Location Services; showing RSSI and channel only. "
    "Reinstall lswifi, or run: pip install pyobjc-framework-CoreLocation"
)
REDACTED_WHILE_AUTHORIZED = (
    f"{_HIDE} even though Location Services is authorized for this Python; "
    "showing RSSI and channel only."
)

_LABELS = {
    AUTHORIZED: "authorized",
    DENIED: "denied",
    RESTRICTED: "restricted",
    NOT_DETERMINED: "not determined",
    NOT_REGISTERED: "unavailable (Python is not code-signed)",
    DISABLED: "turned off",
    UNAVAILABLE: "unavailable",
}
_delegate_class: Any = None


@dataclass(frozen=True)
class LocationAuthorization:
    """CoreLocation's decision for this process"""

    status: str
    granted: bool
    message: str

    def __str__(self) -> str:
        return location_label(self)


_cached: LocationAuthorization | None = None


def location_label(state: LocationAuthorization) -> str:
    """Short text for --supported and --get-interfaces"""
    return _LABELS.get(state.status, state.status)


def current_location_authorization() -> LocationAuthorization | None:
    """The decision already made in this process, if any"""
    return _cached


def load_corelocation():
    """Import CoreLocation. Raises ImportError when the binding is absent."""
    import CoreLocation  # type: ignore[import-not-found,import-untyped]

    return CoreLocation


def location_delegate_class():
    """CLLocationManagerDelegate. Built on first use so import stays lazy."""
    global _delegate_class
    if _delegate_class is not None:
        return _delegate_class
    from Foundation import NSObject  # type: ignore[import-not-found,import-untyped]

    class LocationDelegate(NSObject):
        def locationManagerDidChangeAuthorization_(self, manager):
            return None

        def locationManager_didChangeAuthorizationStatus_(self, manager, status):
            return None

        def locationManager_didUpdateLocations_(self, manager, locations):
            return None

        def locationManager_didFailWithError_(self, manager, error):
            return None

    _delegate_class = LocationDelegate
    return _delegate_class


def attach_location_delegate(manager):
    """Hand CoreLocation a delegate, or None if that binding is missing"""
    try:
        delegate = location_delegate_class().alloc().init()
    except Exception:
        log.debug("location delegate unavailable", exc_info=True)
        return None
    if delegate is None:
        return None
    try:
        manager.setDelegate_(delegate)
    except Exception:
        log.debug("location setDelegate failed", exc_info=True)
        return None
    return delegate


def run_loop_slice(seconds: float) -> None:
    """Run this thread's run loop so CoreLocation can present its prompt.

    Sleeping leaves authorization not determined and never shows the prompt.
    """
    if seconds <= 0:
        return
    from Foundation import NSDate, NSRunLoop  # type: ignore[import-not-found,import-untyped]

    NSRunLoop.currentRunLoop().runUntilDate_(
        NSDate.dateWithTimeIntervalSinceNow_(float(seconds))
    )


def signature_is_registered(text: str) -> bool:
    """True when codesign reports a stable signing identity, not an ad-hoc one"""
    if "Signature=adhoc" in text or "(adhoc)" in text:
        return False
    if "not signed at all" in text:
        return False
    return any(line.strip().startswith("Authority=") for line in text.splitlines())


def interpreter_has_location_identity(executable: str | None = None) -> bool:
    """Whether this interpreter is signed so Location Services can list it.

    Unknown (codesign missing or timed out) is treated as signed, so a
    python.org build is not told it is ad-hoc just because the check failed.
    """
    path = os.path.realpath(executable or sys.executable)
    try:
        completed = subprocess.run(
            ["codesign", "-d", "--verbose=2", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True
    return signature_is_registered(f"{completed.stdout}\n{completed.stderr}")


def wait_budget(interactive: bool | None = None) -> float:
    """Seconds to wait for the prompt. Shorter when stdin is not a terminal."""
    if interactive is None:
        try:
            interactive = sys.stdin.isatty()
        except Exception:
            interactive = False
    if interactive:
        return WAIT_INTERACTIVE_S
    return WAIT_HEADLESS_S


def _read_status(manager) -> int:
    return int(manager.authorizationStatus())


def _services_enabled(corelocation) -> bool | None:
    checker = getattr(corelocation.CLLocationManager, "locationServicesEnabled", None)
    if not callable(checker):
        return None
    try:
        return bool(checker())
    except Exception:
        log.debug("locationServicesEnabled failed", exc_info=True)
        return None


def _ask(manager) -> None:
    try:
        manager.requestWhenInUseAuthorization()
    except Exception:
        log.debug("requestWhenInUseAuthorization failed", exc_info=True)
    try:
        manager.startUpdatingLocation()
    except Exception:
        log.debug("startUpdatingLocation failed", exc_info=True)


def _finish(manager) -> None:
    stopper = getattr(manager, "stopUpdatingLocation", None)
    if callable(stopper):
        try:
            stopper()
        except Exception:
            log.debug("stopUpdatingLocation failed", exc_info=True)
    clearer = getattr(manager, "setDelegate_", None)
    if callable(clearer):
        try:
            clearer(None)
        except Exception:
            log.debug("clearing location delegate failed", exc_info=True)


def _unreadable(error: BaseException) -> str:
    return (
        f"{_HIDE} because Location Services status could not be read "
        f"({error}); showing RSSI and channel only."
    )


def _unknown(status: int) -> str:
    return (
        f"{_HIDE} because Location Services returned an unrecognized "
        f"authorization status ({status}); showing RSSI and channel only."
    )


def _from_code(status: int, *, registered: bool) -> LocationAuthorization:
    if status in _GRANTED:
        return LocationAuthorization(AUTHORIZED, True, "")
    if status == CL_DENIED:
        return LocationAuthorization(DENIED, False, DENIED_MESSAGE)
    if status == CL_RESTRICTED:
        return LocationAuthorization(RESTRICTED, False, RESTRICTED_MESSAGE)
    if status == CL_NOT_DETERMINED:
        if registered:
            return LocationAuthorization(NOT_DETERMINED, False, NOT_DETERMINED_MESSAGE)
        return LocationAuthorization(NOT_REGISTERED, False, NOT_REGISTERED_MESSAGE)
    return LocationAuthorization(UNAVAILABLE, False, _unknown(status))


def _disabled() -> LocationAuthorization:
    return LocationAuthorization(DISABLED, False, DISABLED_MESSAGE)


def _wait_for_decision(
    manager,
    wait_s: float,
    *,
    pump: Callable[[float], None],
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> int:
    if wait_s <= 0:
        return _read_status(manager)
    deadline = monotonic() + wait_s
    status = _read_status(manager)
    spins = 0
    # A run loop that returns immediately must not spin forever.
    limit = int(wait_s / POLL_S) + 2
    while status == CL_NOT_DETERMINED and monotonic() < deadline and spins < limit:
        before = monotonic()
        slice_s = min(POLL_S, deadline - before)
        if slice_s <= 0:
            break
        try:
            pump(slice_s)
        except Exception:
            log.debug("location run loop failed", exc_info=True)
            advanced = False
        else:
            advanced = monotonic() > before
        spins += 1
        status = _read_status(manager)
        if status == CL_NOT_DETERMINED and not advanced:
            sleep(slice_s)
    return status


def query_location_authorization(
    corelocation,
    *,
    registered_check: Callable[[], bool] | None = None,
    wait_s: float | None = None,
    pump: Callable[[float], None] | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    attach: Callable[[Any], Any] | None = None,
) -> LocationAuthorization:
    """Read CoreLocation, and ask for access when the choice is not determined.

    The ask runs `pump` (the thread run loop) until the status changes or
    `wait_s` elapses. Callers on a worker thread should go through the cached
    result of prepare_location_services, which is filled on the main thread.
    """
    if registered_check is None:
        registered_check = interpreter_has_location_identity
    if wait_s is None:
        wait_s = WAIT_INTERACTIVE_S
    if pump is None:
        pump = run_loop_slice
    if sleep is None:
        sleep = time.sleep
    if monotonic is None:
        monotonic = time.monotonic
    if attach is None:
        attach = attach_location_delegate

    manager = corelocation.CLLocationManager.alloc().init()
    delegate = None
    asked = False
    try:
        status = _read_status(manager)
        enabled = _services_enabled(corelocation)
        if enabled is False:
            return _disabled()
        if status in _GRANTED:
            return _from_code(status, registered=True)
        if status != CL_NOT_DETERMINED:
            return _from_code(status, registered=True)
        try:
            registered = bool(registered_check())
        except Exception:
            log.debug("code signature check failed", exc_info=True)
            registered = True
        asked = True
        delegate = attach(manager)
        if delegate is None:
            log.debug("location delegate was not attached")
        _ask(manager)
        budget = min(wait_s, UNSIGNED_WAIT_S) if not registered else wait_s
        status = _wait_for_decision(
            manager,
            budget,
            pump=pump,
            sleep=sleep,
            monotonic=monotonic,
        )
        if status == CL_NOT_DETERMINED and _services_enabled(corelocation) is False:
            return _disabled()
        return _from_code(status, registered=registered)
    finally:
        if asked:
            _finish(manager)
        delegate = None


def prepare_location_services() -> LocationAuthorization:
    """Resolve Location Services once per process."""
    global _cached
    if _cached is not None:
        return _cached
    try:
        corelocation = load_corelocation()
    except ImportError:
        state = LocationAuthorization(UNAVAILABLE, False, CORELOCATION_MISSING)
    else:
        try:
            state = query_location_authorization(
                corelocation,
                wait_s=wait_budget(),
            )
        except Exception as error:
            log.debug("Location Services check failed", exc_info=True)
            state = LocationAuthorization(UNAVAILABLE, False, _unreadable(error))
    log.debug("Location Services status: %s", state.status)
    _cached = state
    return state
