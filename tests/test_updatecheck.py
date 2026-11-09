import json
import logging
import sys

import pytest

from lswifi import __main__ as lswifi_main
from lswifi import appsetup, updatecheck
from tests.test_backends import FakeBackend, parse

DAY = updatecheck.CHECK_INTERVAL_S
INSTALLED = updatecheck.__version__


def newer_than_installed() -> str:
    major, minor, *_rest = (int(part) for part in INSTALLED.split("."))
    return f"{major}.{minor + 1}.0"


@pytest.fixture
def data_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv(updatecheck.DISABLE_ENV, raising=False)
    return tmp_path / "lswifi"


@pytest.fixture
def pypi(monkeypatch):
    calls = []
    answer = {"version": newer_than_installed()}

    def fetch():
        calls.append(1)
        if isinstance(answer["version"], Exception):
            raise answer["version"]
        return answer["version"]

    monkeypatch.setattr(updatecheck, "fetch_latest", fetch)
    return calls, answer


class TestDisabled:
    def test_option(self, data_home):
        assert updatecheck.disabled(parse(["--no-update-check"]))

    @pytest.mark.parametrize(
        ("value", "off"),
        [
            ("1", True),
            ("yes", True),
            ("TRUE", True),
            ("0", False),
            ("", False),
            ("false", False),
        ],
    )
    def test_environment(self, data_home, monkeypatch, value, off):
        monkeypatch.setenv(updatecheck.DISABLE_ENV, value)
        assert updatecheck.disabled(parse([])) is off

    def test_default_is_on(self, data_home):
        assert not updatecheck.disabled(parse([]))


@pytest.mark.parametrize(
    ("latest", "installed", "newer"),
    [
        ("0.6.0", "0.5.0", True),
        ("0.10.0", "0.9.0", True),
        ("1.0", "0.9.9", True),
        ("0.5.0", "0.5.0", False),
        ("0.4.9", "0.5.0", False),
        ("0.6.0rc1", "0.5.0", False),
        ("", "0.5.0", False),
    ],
)
def test_is_newer(latest, installed, newer):
    assert updatecheck.is_newer(latest, installed) is newer


class TestLatestVersion:
    def test_asks_pypi_once_a_day(self, data_home, pypi):
        calls, answer = pypi
        path = str(data_home / updatecheck.STATE_FILE)
        assert updatecheck.latest_version(1000.0, path) == answer["version"]
        assert updatecheck.latest_version(1000.0 + DAY - 1, path) == answer["version"]
        assert len(calls) == 1
        assert updatecheck.latest_version(1000.0 + DAY, path) == answer["version"]
        assert len(calls) == 2
        assert json.loads((data_home / updatecheck.STATE_FILE).read_text()) == {
            "checked": 1000.0 + DAY,
            "latest": answer["version"],
        }

    def test_failed_request_is_quiet_and_waits_a_day(self, data_home, pypi):
        calls, answer = pypi
        answer["version"] = OSError("offline")
        path = str(data_home / updatecheck.STATE_FILE)
        assert updatecheck.latest_version(1000.0, path) is None
        assert updatecheck.latest_version(1000.0 + 60, path) is None
        assert len(calls) == 1

    @pytest.mark.parametrize("content", ["not json", "{}", '{"checked": "soon"}'])
    def test_unreadable_state_asks_again(self, data_home, pypi, content):
        calls, _answer = pypi
        data_home.mkdir()
        (data_home / updatecheck.STATE_FILE).write_text(content)
        updatecheck.latest_version(1000.0, str(data_home / updatecheck.STATE_FILE))
        assert len(calls) == 1

    def test_clock_moved_back_asks_again(self, data_home, pypi):
        calls, _answer = pypi
        path = str(data_home / updatecheck.STATE_FILE)
        updatecheck.latest_version(1000.0 + DAY, path)
        updatecheck.latest_version(1000.0, path)
        assert len(calls) == 2


class TestNotify:
    def test_newer_version_is_logged(self, data_home, pypi, caplog):
        caplog.set_level(logging.INFO)
        updatecheck.notify(parse([]), now=lambda: 1000.0)
        assert (
            f"lswifi {newer_than_installed()} is available (you have {INSTALLED})"
            in caplog.text
        )
        assert "pip install --upgrade lswifi" in caplog.text

    def test_same_version_says_nothing(self, data_home, pypi, caplog):
        caplog.set_level(logging.INFO)
        _calls, answer = pypi
        answer["version"] = INSTALLED
        updatecheck.notify(parse([]), now=lambda: 1000.0)
        assert "is available" not in caplog.text

    @pytest.mark.parametrize("off", ["option", "environment"])
    def test_disabled_does_not_ask_or_write(self, data_home, pypi, monkeypatch, off):
        calls, _answer = pypi
        if off == "environment":
            monkeypatch.setenv(updatecheck.DISABLE_ENV, "1")
        argv = ["--no-update-check"] if off == "option" else []
        updatecheck.notify(parse(argv), now=lambda: 1000.0)
        assert calls == []
        assert not (data_home / updatecheck.STATE_FILE).exists()


def test_message_goes_to_stderr_and_json_stays_clean(
    data_home, pypi, monkeypatch, capsys
):
    monkeypatch.setattr(lswifi_main, "get_backend", lambda: FakeBackend([]))
    monkeypatch.setattr(sys, "argv", ["lswifi", "--list-interfaces", "--json"])
    with pytest.raises(SystemExit):
        lswifi_main.main()
    captured = capsys.readouterr()
    assert "interfaces" in json.loads(captured.out)
    assert "is available" in captured.err


def test_option_is_in_completions():
    from lswifi.completions import get_completions

    assert "--no-update-check" in get_completions([], "--no-up")


def test_option_is_in_help():
    assert "--no-update-check" in appsetup.setup_parser().format_help()


class TestTlsContext:
    def test_falls_back_to_the_system_bundle_without_ca_certificates(
        self, monkeypatch, tmp_path
    ):
        loaded = []

        class Empty:
            def cert_store_stats(self):
                return {"x509_ca": 0}

            def load_verify_locations(self, cafile):
                loaded.append(cafile)

        bundle = tmp_path / "cert.pem"
        bundle.write_text("")
        monkeypatch.setattr(updatecheck.ssl, "create_default_context", Empty)
        updatecheck.tls_context(str(bundle))
        assert loaded == [str(bundle)]

    def test_keeps_the_default_certificates(self, monkeypatch, tmp_path):
        class Loaded:
            def cert_store_stats(self):
                return {"x509_ca": 120}

            def load_verify_locations(self, cafile):
                raise AssertionError("should not load the system bundle")

        monkeypatch.setattr(updatecheck.ssl, "create_default_context", Loaded)
        bundle = tmp_path / "cert.pem"
        bundle.write_text("")
        updatecheck.tls_context(str(bundle))

    def test_verifies_certificates(self):
        context = updatecheck.tls_context()
        assert context.verify_mode == updatecheck.ssl.CERT_REQUIRED
        assert context.check_hostname
