"""Location Services decisions for the macOS backend."""

import os
import subprocess
import sys
import weakref
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from lswifi.backends import macos_location as loc


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Manager:
    def __init__(self, status=loc.CL_AUTHORIZED_ALWAYS, enabled=True):
        self.status = status
        self.enabled = enabled
        self.events = []
        self.delegate = "unset"

    def authorizationStatus(self):
        return self.status

    def requestWhenInUseAuthorization(self):
        self.events.append("request")

    def startUpdatingLocation(self):
        self.events.append("start")

    def stopUpdatingLocation(self):
        self.events.append("stop")

    def setDelegate_(self, delegate):
        self.events.append("delegate")
        self.delegate = delegate


def corelocation_for(manager, enabled=True):
    class CLLocationManager:
        @classmethod
        def alloc(cls):
            return cls

        @classmethod
        def init(cls):
            return manager

        @staticmethod
        def locationServicesEnabled():
            return enabled

    return SimpleNamespace(CLLocationManager=CLLocationManager)


def no_delegate(manager):
    return None


def download_url(message: str):
    start = message.index("https://")
    end = message.find(")", start)
    if end == -1:
        end = len(message)
    return urlparse(message[start:end].rstrip("."))


def assert_download_page(message: str) -> None:
    parsed = download_url(message)
    assert parsed.scheme == "https"
    assert parsed.hostname == "www.python.org"
    assert parsed.path.rstrip("/") == "/downloads/macos"


@pytest.fixture(autouse=True)
def reset_cache(monkeypatch):
    monkeypatch.setattr(loc, "_cached", None)
    monkeypatch.setattr(loc, "_delegate_class", None)


def ask(
    manager,
    *,
    registered=True,
    wait=15.0,
    enabled=True,
    pump=None,
    sleep=None,
    clock=None,
):
    if clock is None:
        clock = Clock()
    if pump is None:

        def pump(seconds, clock=clock):
            clock.now += seconds

    if sleep is None:

        def sleep(seconds):
            raise AssertionError(f"slept {seconds}")

    return loc.query_location_authorization(
        corelocation_for(manager, enabled=enabled),
        registered_check=lambda: registered,
        wait_s=wait,
        pump=pump,
        sleep=sleep,
        monotonic=clock,
        attach=no_delegate,
    )


class TestAlreadyDecided:
    def test_authorized_does_not_ask(self):
        manager = Manager(loc.CL_AUTHORIZED_ALWAYS)
        state = ask(manager)
        assert state.status == loc.AUTHORIZED
        assert state.granted is True
        assert state.message == ""
        assert manager.events == []

    def test_when_in_use_is_a_grant(self):
        manager = Manager(loc.CL_AUTHORIZED_WHEN_IN_USE)
        state = ask(manager)
        assert state.granted is True
        assert manager.events == []

    def test_denied_names_the_settings_pane(self):
        manager = Manager(loc.CL_DENIED)
        state = ask(manager)
        assert state.status == loc.DENIED
        assert "denied" in state.message
        assert "code-signed Python" in state.message
        assert_download_page(state.message)
        assert "uv" in state.message and "Homebrew" in state.message
        assert "pyenv" in state.message
        assert "Enable Python" in state.message
        assert (
            "System Settings > Privacy & Security > Location Services" in state.message
        )
        assert "terminal" not in state.message
        assert "app that runs" not in state.message
        assert manager.events == []

    def test_restricted_points_at_management(self):
        manager = Manager(loc.CL_RESTRICTED)
        state = ask(manager)
        assert state.status == loc.RESTRICTED
        assert "restricted" in state.message
        assert "device management" in state.message
        assert manager.events == []

    def test_services_off_is_not_called_denied(self):
        manager = Manager(loc.CL_DENIED, enabled=False)
        state = ask(manager, enabled=False)
        assert state.status == loc.DISABLED
        assert "turned off" in state.message
        assert (
            "System Settings > Privacy & Security > Location Services" in state.message
        )
        assert manager.events == []

    def test_prior_grant_with_services_off_is_turned_off(self):
        manager = Manager(loc.CL_AUTHORIZED_WHEN_IN_USE)
        state = ask(manager, enabled=False)
        assert state.status == loc.DISABLED
        assert state.granted is False
        assert "turned off" in state.message
        assert manager.events == []

    def test_unknown_code_is_unavailable(self):
        manager = Manager(9)
        state = ask(manager)
        assert state.status == loc.UNAVAILABLE
        assert "9" in state.message
        assert manager.events == []


class TestNotDetermined:
    def test_pumps_the_run_loop_until_granted_and_does_not_sleep(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()
        pumps = []

        def pump(seconds):
            pumps.append(seconds)
            clock.now += seconds
            if len(pumps) == 2:
                manager.status = loc.CL_AUTHORIZED_WHEN_IN_USE

        state = ask(manager, pump=pump, clock=clock)
        assert state.granted is True
        assert pumps == [loc.POLL_S, loc.POLL_S]
        assert manager.events == ["request", "start", "stop", "delegate"]
        assert manager.delegate is None

    def test_delegate_is_set_before_the_request_and_cleared_after(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        order = []

        def attach(found):
            order.append("delegate")
            found.setDelegate_("stub")
            return "stub"

        def pump(seconds):
            order.append("pump")
            manager.status = loc.CL_AUTHORIZED_ALWAYS

        clock = Clock()
        state = loc.query_location_authorization(
            corelocation_for(manager),
            registered_check=lambda: True,
            wait_s=15,
            pump=pump,
            sleep=lambda seconds: (_ for _ in ()).throw(AssertionError("slept")),
            monotonic=clock,
            attach=attach,
        )
        assert state.granted is True
        assert order == ["delegate", "pump"]
        assert manager.events[0] == "delegate"
        assert manager.events[1:3] == ["request", "start"]
        assert manager.events[-2:] == ["stop", "delegate"]
        assert manager.delegate is None

    def test_manager_and_delegate_stay_alive_for_the_wait(self):
        alive = {}

        class WeakDelegateManager(Manager):
            def __init__(self, status):
                self.status = status
                self.enabled = True
                self.events = []
                self._delegate_ref = None

            def setDelegate_(self, delegate):
                self.events.append("delegate")
                if delegate is None:
                    self._delegate_ref = None
                else:
                    self._delegate_ref = weakref.ref(delegate)

            @property
            def delegate(self):
                ref = getattr(self, "_delegate_ref", None)
                return None if ref is None else ref()

        def attach(manager):
            delegate = type("LocationDelegate", (), {})()
            manager.setDelegate_(delegate)
            alive["manager"] = weakref.ref(manager)
            alive["delegate"] = weakref.ref(delegate)
            return delegate

        def pump(seconds):
            assert alive["manager"]() is not None
            assert alive["delegate"]() is not None
            alive["manager"]().status = loc.CL_AUTHORIZED_ALWAYS

        clock = Clock()

        class CLLocationManager:
            @classmethod
            def alloc(cls):
                return cls

            @classmethod
            def init(cls):
                return WeakDelegateManager(loc.CL_NOT_DETERMINED)

            @staticmethod
            def locationServicesEnabled():
                return True

        state = loc.query_location_authorization(
            SimpleNamespace(CLLocationManager=CLLocationManager),
            registered_check=lambda: True,
            wait_s=15,
            pump=pump,
            sleep=lambda seconds: (_ for _ in ()).throw(AssertionError("slept")),
            monotonic=clock,
            attach=attach,
        )
        assert state.granted is True
        assert alive["delegate"]() is None
        assert alive["manager"]() is None

    def test_user_denies_during_the_wait(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()

        def pump(seconds):
            clock.now += seconds
            manager.status = loc.CL_DENIED

        state = ask(manager, pump=pump, clock=clock)
        assert state.status == loc.DENIED
        assert manager.events[-2:] == ["stop", "delegate"]

    def test_signed_interpreter_stops_at_the_budget(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()
        pumps = []

        def pump(seconds):
            pumps.append(seconds)
            clock.now += seconds

        state = ask(manager, wait=1.0, pump=pump, clock=clock)
        assert state.status == loc.NOT_DETERMINED
        assert "not determined" in state.message
        assert "Click Allow in the macOS prompt and run lswifi again." in state.message
        assert "If no prompt appears" in state.message
        assert "use the + button and pick" in state.message
        assert os.path.realpath(sys.executable) in state.message
        assert "turn it on, and run lswifi again." in state.message
        assert (
            "System Settings > Privacy & Security > Location Services" in state.message
        )
        assert "code-signed Python" in state.message
        assert_download_page(state.message)
        assert "Enable Python" in state.message
        assert "uv" in state.message
        assert sum(pumps) == pytest.approx(1.0)
        assert sum(pumps) < loc.WAIT_INTERACTIVE_S

    def test_unsigned_interpreter_asks_but_does_not_use_the_long_wait(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()
        pumps = []

        def pump(seconds):
            pumps.append(seconds)
            clock.now += seconds

        state = ask(
            manager,
            registered=False,
            wait=loc.WAIT_INTERACTIVE_S,
            pump=pump,
            clock=clock,
        )
        assert state.status == loc.NOT_REGISTERED
        assert "not code-signed" in state.message
        assert_download_page(state.message)
        assert "uv" in state.message
        assert "Homebrew" in state.message and "pyenv" in state.message
        assert "Enable Python" in state.message
        assert "cannot be granted" in state.message
        assert "request" in manager.events
        assert sum(pumps) == pytest.approx(loc.UNSIGNED_WAIT_S)
        assert sum(pumps) < loc.WAIT_HEADLESS_S

    def test_unsigned_interpreter_that_is_granted_anyway(self):
        manager = Manager(loc.CL_NOT_DETERMINED)

        def pump(seconds):
            manager.status = loc.CL_AUTHORIZED_ALWAYS

        state = ask(manager, registered=False, pump=pump)
        assert state.granted is True

    def test_run_loop_that_returns_immediately_still_ends(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()
        sleeps = []

        def pump(seconds):
            return None

        def sleep(seconds):
            sleeps.append(seconds)
            clock.now += seconds

        state = ask(
            manager,
            wait=1.0,
            pump=pump,
            sleep=sleep,
            clock=clock,
        )
        assert state.status == loc.NOT_DETERMINED
        assert sum(sleeps) == pytest.approx(1.0)

    def test_frozen_clock_cannot_spin_forever(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        pumps = []

        def pump(seconds):
            pumps.append(seconds)

        state = ask(
            manager,
            wait=1.0,
            pump=pump,
            sleep=lambda seconds: None,
            clock=Clock(),
        )
        assert state.status == loc.NOT_DETERMINED
        assert len(pumps) <= int(1.0 / loc.POLL_S) + 2

    def test_failed_pump_still_stops_location_updates(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        clock = Clock()

        def pump(seconds):
            raise RuntimeError("run loop")

        def sleep(seconds):
            clock.now += seconds

        state = ask(
            manager,
            wait=0.5,
            pump=pump,
            sleep=sleep,
            clock=clock,
        )
        assert state.status == loc.NOT_DETERMINED
        assert manager.events[-2:] == ["stop", "delegate"]

    def test_services_off_after_the_wait_is_disabled(self):
        manager = Manager(loc.CL_NOT_DETERMINED)
        enabled = {"on": True}

        class CLLocationManager:
            @classmethod
            def alloc(cls):
                return cls

            @classmethod
            def init(cls):
                return manager

            @staticmethod
            def locationServicesEnabled():
                return enabled["on"]

        clock = Clock()

        def pump(seconds):
            clock.now += seconds
            enabled["on"] = False

        state = loc.query_location_authorization(
            SimpleNamespace(CLLocationManager=CLLocationManager),
            registered_check=lambda: True,
            wait_s=15,
            pump=pump,
            sleep=lambda seconds: None,
            monotonic=clock,
            attach=no_delegate,
        )
        assert state.status == loc.DISABLED
        assert "stop" in manager.events


class TestRunLoop:
    def test_slice_uses_the_run_loop_and_does_not_sleep(self, monkeypatch):
        calls = []

        class Date:
            @staticmethod
            def dateWithTimeIntervalSinceNow_(seconds):
                calls.append(("date", seconds))
                return seconds

        class Loop:
            @staticmethod
            def currentRunLoop():
                return Loop

            @staticmethod
            def runUntilDate_(when):
                calls.append(("run", when))

        monkeypatch.setitem(
            sys.modules,
            "Foundation",
            SimpleNamespace(NSDate=Date, NSRunLoop=Loop),
        )
        monkeypatch.setattr(
            loc.time,
            "sleep",
            lambda seconds: (_ for _ in ()).throw(AssertionError("slept")),
        )
        loc.run_loop_slice(0.25)
        assert calls == [("date", 0.25), ("run", 0.25)]

    def test_non_positive_slice_does_not_touch_foundation(self):
        loc.run_loop_slice(0)
        loc.run_loop_slice(-1)

    def test_missing_delegate_still_asks(self, monkeypatch):
        manager = Manager(loc.CL_NOT_DETERMINED)

        def broken():
            raise ImportError("Foundation")

        monkeypatch.setattr(loc, "location_delegate_class", broken)
        clock = Clock()

        def pump(seconds):
            clock.now += seconds
            manager.status = loc.CL_AUTHORIZED_ALWAYS

        state = loc.query_location_authorization(
            corelocation_for(manager),
            registered_check=lambda: True,
            wait_s=1,
            pump=pump,
            sleep=lambda seconds: (_ for _ in ()).throw(AssertionError("slept")),
            monotonic=clock,
        )
        assert state.granted is True
        assert manager.events[:2] == ["request", "start"]


class TestSignature:
    @pytest.mark.parametrize(
        "text, registered",
        [
            (
                "Authority=Developer ID Application: Example Builder\n",
                True,
            ),
            ("Authority=Software Signing\nAuthority=Apple Root CA\n", True),
            ("Signature=adhoc\n", False),
            ("flags=0x2(adhoc)\n", False),
            ("code object is not signed at all\n", False),
            ("Identifier=python3\n", False),
        ],
    )
    def test_signature_text(self, text, registered):
        assert loc.signature_is_registered(text) is registered

    def test_codesign_follows_the_real_binary(self, monkeypatch, tmp_path):
        target = tmp_path / "python"
        target.write_text("binary")
        link = tmp_path / "venv-python"
        link.symlink_to(target)
        seen = {}

        def run(argv, **kwargs):
            seen["argv"] = argv
            seen["timeout"] = kwargs.get("timeout")
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr="Authority=Developer ID Application: Python Software Foundation\n",
            )

        monkeypatch.setattr(loc.subprocess, "run", run)
        assert loc.interpreter_has_location_identity(str(link)) is True
        assert seen["argv"][-1] == str(target.resolve())
        assert seen["timeout"] == 3

    def test_missing_codesign_does_not_claim_the_interpreter_is_unsigned(
        self, monkeypatch
    ):
        def run(*args, **kwargs):
            raise FileNotFoundError("codesign")

        monkeypatch.setattr(loc.subprocess, "run", run)
        assert loc.interpreter_has_location_identity("/usr/bin/python3") is True

    def test_codesign_timeout_does_not_claim_unsigned(self, monkeypatch):
        def run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="codesign", timeout=3)

        monkeypatch.setattr(loc.subprocess, "run", run)
        assert loc.interpreter_has_location_identity() is True


class TestPrepare:
    def test_import_error_is_unavailable_and_cached(self, monkeypatch):
        calls = []

        def load():
            calls.append(1)
            raise ImportError("no CoreLocation")

        monkeypatch.setattr(loc, "load_corelocation", load)
        first = loc.prepare_location_services()
        second = loc.prepare_location_services()
        assert first.status == loc.UNAVAILABLE
        assert "pyobjc-framework-CoreLocation" in first.message
        assert second is first
        assert calls == [1]

    def test_manager_failure_is_unavailable_and_cached(self, monkeypatch):
        class CLLocationManager:
            @classmethod
            def alloc(cls):
                return cls

            @classmethod
            def init(cls):
                raise RuntimeError("tcc")

        calls = []

        def load():
            calls.append(1)
            return SimpleNamespace(CLLocationManager=CLLocationManager)

        monkeypatch.setattr(loc, "load_corelocation", load)
        state = loc.prepare_location_services()
        again = loc.prepare_location_services()
        assert state.status == loc.UNAVAILABLE
        assert "tcc" in state.message
        assert again is state
        assert calls == [1]

    def test_uses_the_wait_budget_once(self, monkeypatch):
        seen = {}

        def query(corelocation, *, wait_s=None, **kwargs):
            seen["wait_s"] = wait_s
            return loc.LocationAuthorization(loc.AUTHORIZED, True, "")

        monkeypatch.setattr(loc, "load_corelocation", lambda: object())
        monkeypatch.setattr(loc, "query_location_authorization", query)
        monkeypatch.setattr(loc, "wait_budget", lambda interactive=None: 1.0)
        assert loc.prepare_location_services().granted is True
        assert loc.prepare_location_services().granted is True
        assert seen == {"wait_s": 1.0}

    def test_wait_budget_follows_the_terminal(self, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert loc.wait_budget() == loc.WAIT_INTERACTIVE_S
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        assert loc.wait_budget() == loc.WAIT_HEADLESS_S
        monkeypatch.setattr(
            sys.stdin, "isatty", lambda: (_ for _ in ()).throw(ValueError("closed"))
        )
        assert loc.wait_budget() == loc.WAIT_HEADLESS_S

    def test_default_wait_pumps_the_run_loop_hook(self, monkeypatch):
        manager = Manager(loc.CL_NOT_DETERMINED)
        pumps = []
        clock = Clock()

        def pump(seconds):
            pumps.append(seconds)
            clock.now += seconds
            if sum(pumps) >= 0.5:
                manager.status = loc.CL_AUTHORIZED_ALWAYS

        monkeypatch.setattr(loc, "load_corelocation", lambda: corelocation_for(manager))
        monkeypatch.setattr(
            loc, "interpreter_has_location_identity", lambda executable=None: True
        )
        monkeypatch.setattr(loc, "run_loop_slice", pump)
        monkeypatch.setattr(loc, "wait_budget", lambda interactive=None: 15.0)
        monkeypatch.setattr(loc.time, "monotonic", clock)
        monkeypatch.setattr(
            loc.time,
            "sleep",
            lambda seconds: (_ for _ in ()).throw(AssertionError("slept")),
        )
        state = loc.prepare_location_services()
        assert state.granted is True
        assert pumps
        assert "request" in manager.events
        assert "start" in manager.events
        assert manager.events[-2:] == ["stop", "delegate"]
