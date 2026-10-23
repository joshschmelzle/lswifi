# -*- encoding: utf-8

"""macOS --watchevents (CoreWLAN events + airportd log markers).

Fakes only; never imports CoreWLAN, so it runs on any OS.
"""

import io
import logging
import sys
import threading
from types import SimpleNamespace

import pytest

from lswifi.backends import macos
from lswifi.backends.base import InterfaceInfo
from lswifi.backends.macos_events import (
    CW_EVENT_TYPES,
    AirportdLogClassifier,
    AirportdLogReader,
    EventFormatter,
    LinkState,
    LogEvent,
    MacOSEventWatcher,
    read_link_state,
    reason_text,
)

MAC = "c0:c7:db:00:00:01"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeChannel:
    def __init__(self, number, band, width):
        self._n, self._b, self._w = number, band, width

    def channelNumber(self):
        return self._n

    def channelBand(self):
        return self._b

    def channelWidth(self):
        return self._w


class FakeCWInterface:
    def __init__(self, **kw):
        self.power = True
        self.mode = 1
        self.ssid = b"ExampleNet"
        self.bssid_value = "02:00:00:00:00:14"
        self.channel = FakeChannel(44, macos.CW_CHANNEL_BAND_5GHZ, 1)
        self.rssi = -44
        self.noise = -94
        self.rate = 86.0
        self.country = "US"
        self.cached = [object()] * 78
        self.__dict__.update(kw)

    def interfaceName(self):
        return "en0"

    def hardwareAddress(self):
        return MAC

    def powerOn(self):
        return self.power

    def interfaceMode(self):
        return self.mode

    def ssidData(self):
        return self.ssid

    def bssid(self):
        return self.bssid_value

    def wlanChannel(self):
        return self.channel

    def rssiValue(self):
        return self.rssi

    def noiseMeasurement(self):
        return self.noise

    def transmitRate(self):
        return self.rate

    def countryCode(self):
        return self.country

    def cachedScanResults(self):
        return self.cached


def state(**kw):
    base = dict(
        power=True,
        connected=True,
        ssid="ExampleNet",
        bssid="02:00:00:00:00:14",
        channel=44,
        band="5 GHz",
        width_mhz=20,
        frequency_mhz=5220,
        rssi=-44,
        noise=-94,
        tx_rate=86.0,
        mode=1,
        country_code="US",
    )
    base.update(kw)
    return LinkState(**base)


@pytest.fixture
def formatter():
    clock = Clock()
    fmt = EventFormatter(MAC, clock)
    fmt.state_change(state())  # baseline "watching" line
    fmt.clock_ref = clock
    return fmt


class TestReadLinkState:
    def test_connected(self):
        snap = read_link_state(FakeCWInterface())
        assert snap.connected and snap.power
        assert snap.bssid == "02:00:00:00:00:14"
        assert snap.ssid == "ExampleNet"
        assert (snap.channel, snap.band, snap.width_mhz) == (44, "5 GHz", 20)
        assert snap.frequency_mhz == 5220
        assert (snap.rssi, snap.noise, snap.tx_rate) == (-44, -94, 86.0)

    def test_redacted(self):
        snap = read_link_state(FakeCWInterface(ssid=None, bssid_value=None, country=None))
        assert snap.connected and snap.redacted
        assert snap.bssid == "" and snap.ssid == "" and snap.country_code == ""
        assert snap.channel == 44

    def test_power_off(self):
        snap = read_link_state(FakeCWInterface(power=False))
        assert not snap.power and not snap.connected and snap.channel is None

    def test_disconnected(self):
        snap = read_link_state(FakeCWInterface(mode=0))
        assert snap.power and not snap.connected and snap.bssid == ""


class TestEventFormatter:
    def test_first_line_is_watching(self):
        fmt = EventFormatter(MAC, Clock())
        (line,) = fmt.state_change(state())
        assert line.startswith(f"({MAC}), bssid: (02:00:00:00:00:14), freq: (5220)")
        assert "ssid: (ExampleNet), rssi: (-44), event: (watching)" in line
        assert "channel: (44@20 5 GHz), noise: (-94), tx_rate: (86 Mbps)" in line

    def test_no_change_no_line(self, formatter):
        assert formatter.state_change(state()) == []

    def test_roam(self, formatter):
        new = state(
            bssid="02:00:00:00:00:08",
            channel=149,
            width_mhz=80,
            frequency_mhz=5745,
            rssi=-58,
            tx_rate=576.0,
        )
        (line,) = formatter.state_change(new)
        assert "bssid: (02:00:00:00:00:08), freq: (5745)" in line
        assert "rssi: (-58), event: (roamed)" in line
        assert "old_bssid: (02:00:00:00:00:14), old_freq: (5220), old_rssi: (-44)" in line
        assert " -> " not in line
        assert "channel: (149@80 5 GHz)" in line and "old_channel: (44@20 5 GHz)" in line

    def test_disconnect_then_connect(self, formatter):
        (down,) = formatter.state_change(state(connected=False, bssid="", ssid="", mode=0))
        assert "bssid: (02:00:00:00:00:14)" in down and "event: (disconnected)" in down
        (up,) = formatter.state_change(state())
        assert "event: (connected)" in up and "channel: (44@20 5 GHz)" in up

    def test_nil_bssid_burst_between_two_aps_is_one_roam(self, formatter):
        # Bugbot A: a nil BSSID mid-roam must not hide the roam
        assert formatter.state_change(state(bssid="")) == []
        new = state(bssid="02:00:00:00:00:08", channel=149, frequency_mhz=5745)
        (line,) = formatter.state_change(new)
        assert "event: (roamed)" in line and "old_bssid: (02:00:00:00:00:14)" in line
        assert formatter.state_change(new) == []

    def test_nil_bssid_burst_same_ap_is_quiet(self, formatter):
        assert formatter.state_change(state(bssid="")) == []
        assert formatter.state_change(state()) == []

    def test_disconnect_then_connect_same_bssid_is_not_a_roam(self, formatter):
        # what a Mac does on every sleep/wake cycle
        down = state(connected=False, bssid="", ssid="", mode=0)
        (line,) = formatter.state_change(down)
        assert "event: (disconnected)" in line
        (up,) = formatter.state_change(state())
        assert "event: (connected)" in up and "old_bssid" not in up
        assert "roamed" not in up

    def test_reconnect_to_other_ap_carries_old_bssid(self, formatter):
        formatter.state_change(state(connected=False, bssid="", ssid="", mode=0))
        (up,) = formatter.state_change(state(bssid="02:00:00:00:00:08"))
        assert "event: (connected)" in up and "old_bssid: (02:00:00:00:00:14)" in up
        assert up.record["old_bssid"] == "02:00:00:00:00:14"

    def test_reconnect_bssid_arrives_late_is_not_a_roam(self, formatter):
        formatter.state_change(state(connected=False, bssid="", ssid="", mode=0))
        (up,) = formatter.state_change(state(bssid=""))
        assert "event: (connected)" in up
        assert formatter.state_change(state(bssid="02:00:00:00:00:08")) == []

    def test_power_off_and_on(self, formatter):
        (off,) = formatter.state_change(LinkState(power=False, country_code="US"))
        assert off == f"({MAC}), event: (power_off)"
        lines = formatter.state_change(LinkState(power=True, country_code="US"))
        assert lines == [f"({MAC}), event: (power_on)"]
        (up,) = formatter.state_change(state())
        assert "event: (connected)" in up

    def test_channel_change_same_bssid(self, formatter):
        (line,) = formatter.state_change(state(channel=48, frequency_mhz=5240))
        assert "event: (channel_change), channel: (48@20 5 GHz), old_channel: (44@20 5 GHz)" in line

    def test_ssid_change(self, formatter):
        (line,) = formatter.state_change(state(ssid="VAP3"))
        assert "event: (ssid_change), old_ssid: (ExampleNet)" in line

    def test_country_code(self, formatter):
        (line,) = formatter.state_change(state(country_code="CA"))
        assert line.endswith("country_code: (CA), old_country_code: (US)")

    def test_redacted_omits_identity_and_flags_warning(self):
        fmt = EventFormatter(MAC, Clock())
        (line,) = fmt.state_change(state(bssid="", ssid=""))
        assert "bssid" not in line and "ssid" not in line
        assert "freq: (5220), rssi: (-44), event: (watching)" in line
        assert fmt.location_warning_needed

    def test_link_quality_throttled(self, formatter):
        clock = formatter.clock_ref
        clock.now += 1
        assert formatter.link_quality(state(rssi=-60)) == []  # < 2 s
        clock.now += 2
        assert formatter.link_quality(state(rssi=-47)) == []  # 3 dB
        (line,) = formatter.link_quality(state(rssi=-50))
        assert "event: (signal_quality_change), old_rssi: (-44)" in line
        clock.now += 3
        assert formatter.link_quality(state(rssi=-52)) == []
        (rate,) = formatter.link_quality(state(rssi=-52, tx_rate=40.0))
        assert "tx_rate: (40 Mbps)" in rate

    def test_link_quality_ignored_when_disconnected(self, formatter):
        assert formatter.link_quality(state(connected=False, rssi=None)) == []

    def test_scan_cache(self, formatter):
        (line,) = formatter.scan_cache(state(), 78)
        assert line.endswith("event: (scan_cache_updated), scan: (78 BSSIDs found)")

    def test_squelch_repeats(self, formatter):
        clock = formatter.clock_ref
        line = formatter.scan_cache(state(), 78)[0]
        assert not formatter.squelch(line)
        assert formatter.squelch(line)
        clock.now += 3
        assert not formatter.squelch(line)


TIMING = (
    "2026-10-03 19:41:04.000 Df airportd[483:1] [com.apple.WiFiManager:] "
    "AUTO-JOIN: Updated join status (uuid=B1D76, intf=en0, "
    "assoc=2026-10-03 19:41:01.328 -0400 (272ms), auth=2026-10-03 19:41:02.004 -0400 (948ms), "
    "linkup=2026-10-03 19:41:01.338 -0400 (281ms), ipv4=2026-10-03 19:41:02.392 -0400 (1336ms), "
    "ipv6=2026-10-03 19:41:02.599 -0400 (1542ms))"
)


TS = "2026-10-22 20:12:38.519"
_ROAM_PREFIX_TEXT = (
    f"{TS} Df airportd[423:43c703] [com.apple.WiFiManager:] Roam: <airport[423]> "
    "-[CWXPCInterfaceContext __triggerRoamWithInterface:roamToBssid:roamToChannel:"
    "channelFlags:bandPreference:roamFlags:]: "
)
# real macOS 26 airportd output (log stream --style compact)
ROAM_LINES = [
    _ROAM_PREFIX_TEXT + "BEST CONNECTED ROAM triggered",
    _ROAM_PREFIX_TEXT + "Requesting Roam : {",
    "    BSSID = {length = 6, bytes = 0xffffffffffff};",
    "}",
]
SLEEP_WAKE_LINES = [
    f"{TS} Df airportd[423:13f7] [com.apple.WiFiManager:] WoW: <airport[423]> "
    "_acknowledgeSleepEvent: Acknowledging sleep event, connection[0x1] "
    "token[0x00610011], gPMConnection[0x1]",
    f"{TS} Df airportd[423:43c337] [com.apple.WiFiManager:] AutoJoin: <airport[423]> "
    "airportdProcessWake: Received dark wake event for en0",
    f"{TS} Df airportd[423:43c9b5] [com.apple.WiFiManager:] AutoJoin: <airport[423]> "
    "airportdProcessWake: Received dark wake event for en0",
    f"{TS} Df airportd[423:13f7] [com.apple.WiFiManager:] Info: <airport[423]> "
    "_clamshellNotificationCallback: Clamshell state changed (closed=0, causesSleep=0)",
    f"{TS} Df airportd[423:43ce2d] [com.apple.WiFiManager:] AutoJoin: <airport[423]> "
    "airportdProcessWake: Received full wake event for en0",
    f"{TS} Df airportd[423:13f7] [com.apple.WiFiManager:] AutoJoin: <airport[423]> "
    "airportdProcessWake: Received full wake event for en0",
]


class TestAirportdLogClassifier:
    def test_deauth_with_reason(self):
        event = AirportdLogClassifier().classify(
            "2026-10-05 00:00:00.000 Df airportd[483:abcd] [com.apple.WiFiManager:] "
            "[corewifi] Received Deauth from D0:4D:C6:B2:78:40 with Reason 4"
        )
        assert event == LogEvent(
            "deauth", "from: (d0:4d:c6:b2:78:40), reason: (4 disassociated due to inactivity)"
        )

    def test_disassoc_redacted(self):
        event = AirportdLogClassifier().classify(
            "... Received Disassoc from <redacted> with Reason 8"
        )
        assert event == LogEvent(
            "disassoc", "reason: (8 disassociated because STA is leaving)"
        )

    def test_join_timing_once(self):
        classifier = AirportdLogClassifier()
        event = classifier.classify(TIMING)
        assert event is not None and event.event == "join_timing"
        assert event.detail.startswith("assoc: (272 ms), auth: (948 ms), linkup: (281 ms)")
        assert classifier.classify(TIMING) is None  # same uuid

    def test_partial_join_timing_skipped(self):
        assert AirportdLogClassifier().classify(
            "AUTO-JOIN: Updated join status (uuid=X, assoc=2026 (12ms))"
        ) is None

    def test_roam_trigger_and_request_block_one_event(self):
        classifier = AirportdLogClassifier(Clock())
        events = []
        for line in ROAM_LINES:
            events += classifier.feed(line + "\n")
        assert events == [
            LogEvent(
                "roam_requested",
                "trigger: (best_connected_roam), roam_target_bssid: (any)",
                {"trigger": "best_connected_roam", "roam_target_bssid": "any"},
            )
        ]
        assert classifier.feed(f"{TS} Df airportd[423:1] noise\n") == []

    def test_roam_request_with_target(self):
        classifier = AirportdLogClassifier(Clock())
        lines = [
            ROAM_LINES[1],
            "    BSSID = {length = 6, bytes = 0x020000000008};",
            "    CHANNEL = 149;",
            '    REASON = "LowRSSI";',
            "}",
        ]
        events = [e for line in lines for e in classifier.feed(line)]
        assert events[0].fields == {
            "roam_target_bssid": "02:00:00:00:00:08",
            "roam_target_channel": 149,
            "roam_reason": "LowRSSI",
        }
        assert "\n" not in events[0].detail and "{" not in events[0].detail

    def test_requesting_roam_line_alone_parses_payload(self):
        # Bugbot B: the detail was a truncated copy of the whole line
        (event,) = AirportdLogClassifier(Clock()).feed(
            ROAM_LINES[1] + " BSSID = {length = 6, bytes = 0x020000000008}; }\n"
        )
        assert event == LogEvent(
            "roam_requested",
            "roam_target_bssid: (02:00:00:00:00:08)",
            {"roam_target_bssid": "02:00:00:00:00:08"},
        )
        assert "CWXPCInterfaceContext" not in event.detail

    def test_one_line_roam_block_keeps_fields_after_bssid(self):
        # Bugbot: the NSData "}" in BSSID must not end the block early
        (event,) = AirportdLogClassifier(Clock()).feed(
            ROAM_LINES[1]
            + " BSSID = {length = 6, bytes = 0x020000000008}; CHANNEL = 149;"
            + ' REASON = "LowRSSI"; }\n'
        )
        assert event.fields == {
            "roam_target_bssid": "02:00:00:00:00:08",
            "roam_target_channel": 149,
            "roam_reason": "LowRSSI",
        }

    def test_channel_flags_do_not_override_target_channel(self):
        # Bugbot: only the CHANNEL key is the target, not CHANNEL_FLAGS etc.
        classifier = AirportdLogClassifier(Clock())
        lines = [
            ROAM_LINES[1],
            "    CHANNEL = 149;",
            "    CHANNEL_FLAGS = 8210;",
            "    CHANNELFLAGS = 1040;",
            "}",
        ]
        events = [e for line in lines for e in classifier.feed(line)]
        assert events[0].fields == {"roam_target_channel": 149}
        assert "roam_target_channel: (149)" in events[0].detail
        assert "8210" not in events[0].detail and "1040" not in events[0].detail

    def test_roam_block_cut_short_by_next_entry(self):
        classifier = AirportdLogClassifier(Clock())
        classifier.feed(ROAM_LINES[1])
        events = classifier.feed(f"{TS} Df airportd[423:1] something else")
        assert [e.event for e in events] == ["roam_requested"]

    def test_roam_triggered_alone(self):
        classifier = AirportdLogClassifier(Clock())
        assert classifier.feed(
            "2026-10-04 16:41:52.359 Df airportd[483:e6] [com.apple.WiFiManager:] "
            "Roam: <airport[483]> BEST CONNECTED ROAM triggered, reason=RSSI"
        ) == []
        (event,) = classifier.feed(f"{TS} Df airportd[423:1] unrelated")
        assert event == LogEvent(
            "roam_triggered",
            "trigger: (best_connected_roam), roam_reason: (RSSI)",
            {"trigger": "best_connected_roam", "roam_reason": "RSSI"},
        )
        assert classifier.flush() == []

    def test_flush_pending_trigger(self):
        classifier = AirportdLogClassifier(Clock())
        classifier.feed(ROAM_LINES[0])
        assert [e.event for e in classifier.flush()] == ["roam_triggered"]

    def test_sleep_wake_lid(self):
        clock = Clock()
        classifier = AirportdLogClassifier(clock)
        events = []
        for line in SLEEP_WAKE_LINES:
            clock.now += 0.3
            events += classifier.feed(line + "\n")
        assert [(e.event, e.detail) for e in events] == [
            ("system_sleep", ""),
            ("system_wake", "wake: (dark)"),
            ("lid_opened", ""),
            ("system_wake", "wake: (full)"),
        ]
        assert events[1].fields == {"wake": "dark"}

    def test_wake_repeats_after_window(self):
        clock = Clock()
        classifier = AirportdLogClassifier(clock)
        line = SLEEP_WAKE_LINES[1]
        assert classifier.classify(line) is not None
        assert classifier.classify(line) is None
        clock.now += 60
        assert classifier.classify(line) is not None

    def test_pm_connection_sleep_ack_ignored(self):
        assert AirportdLogClassifier().classify(
            f"{TS} Df airportd[423:13f7] [com.apple.WiFiManager:] Driver Discovery: "
            "<airport[423]> _PMConnectionHandler: Acknowledging sleep event, "
            "connection[0x1] token[0x0]"
        ) is None

    @pytest.mark.parametrize(
        "line",
        [
            "Roam: <airport[483]> Found matching scan result with matching SSID",
            "[corewifi] BEGIN REQ [GET POWER] (pid=42598 proc=WiFi Explorer)",
            "Driver Event: APPLE80211_M_ROAMED/32 (en0)",
        ],
    )
    def test_noise_ignored(self, line):
        assert AirportdLogClassifier().classify(line) is None

    def test_reason_text(self):
        assert reason_text(15) == "4-way handshake timeout"
        assert reason_text(999) == "reserved/unknown"


class FakeProcess:
    def __init__(self, lines, code=0):
        self.stdout = io.StringIO("".join(lines))
        self.code = code
        self.terminated = False

    def wait(self, timeout=None):
        return self.code

    def poll(self):
        return None if not self.terminated else self.code

    def terminate(self):
        self.terminated = True


class TestAirportdLogReader:
    def test_reads_and_classifies(self):
        events = []
        proc = FakeProcess(
            ["noise\n", TIMING + "\n"] + [line + "\n" for line in ROAM_LINES]
        )
        reader = AirportdLogReader(events.append, popen=lambda *a, **k: proc)
        assert reader.start()
        reader.thread.join(2)
        assert [e.event for e in events] == ["join_timing", "roam_requested"]
        reader.stop()
        assert proc.terminated

    def test_not_admin_one_info_line(self, caplog):
        proc = FakeProcess(["log: Must be admin to run 'stream' command\n"], code=64)
        reader = AirportdLogReader(lambda e: None, popen=lambda *a, **k: proc)
        with caplog.at_level(logging.INFO):
            reader.start()
            reader.thread.join(2)
        (record,) = [r for r in caplog.records if "airportd" in r.getMessage()]
        assert "Must be admin" in record.getMessage()

    def test_stop_while_reading_is_quiet(self, caplog):
        gate = threading.Event()

        class SlowStdout:
            def __iter__(self):
                gate.wait(2)
                return iter(())

        proc = FakeProcess([], code=-15)
        proc.stdout = SlowStdout()
        reader = AirportdLogReader(lambda e: None, popen=lambda *a, **k: proc)
        with caplog.at_level(logging.INFO):
            reader.start()
            reader.stop()
            gate.set()
            reader.thread.join(2)
        assert proc.terminated
        assert caplog.text == ""

    def test_missing_log_binary(self, caplog):
        def boom(*a, **k):
            raise FileNotFoundError("/usr/bin/log")

        with caplog.at_level(logging.INFO):
            assert AirportdLogReader(lambda e: None, popen=boom).start() is False
        assert "CoreWLAN events only" in caplog.text


class FakeClient:
    def __init__(self, cw, refuse=()):
        self.cw = cw
        self.refuse = set(refuse)
        self.started = []
        self.delegate = "unset"
        self.stopped = False

    def interfaceWithName_(self, name):
        return self.cw

    def startMonitoringEventWithType_error_(self, value, error):
        if value in self.refuse:
            return (False, "nope")
        self.started.append(value)
        return (True, None)

    def stopMonitoringAllEventsAndReturnError_(self, error):
        self.stopped = True
        return (True, None)

    def setDelegate_(self, delegate):
        self.delegate = delegate


def make_watcher(cw=None, clock=None, debug=logging.INFO):
    cw = cw or FakeCWInterface()
    info = InterfaceInfo(
        connection_name="en0",
        description="Wi-Fi (en0)",
        guid_string="",
        mac=MAC,
        state_string="connected",
        native=cw,
    )
    lines = []
    watcher = MacOSEventWatcher(
        FakeClient(cw),
        [info],
        SimpleNamespace(syslog=None, debug=debug),
        emit=lines.append,
        clock=clock or Clock(),
    )
    return watcher, cw, lines


class TestMacOSEventWatcher:
    def test_roam_via_bssid_event_prints_once(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        cw.bssid_value = "02:00:00:00:00:08"
        cw.channel = FakeChannel(149, macos.CW_CHANNEL_BAND_5GHZ, 3)
        cw.rssi = -60
        for kind in ("bssid", "link", "ssid"):  # one roam, three callbacks
            watcher.on_event(kind, "en0")
        assert len(lines) == 2
        assert "event: (roamed)" in lines[1]
        assert "freq: (5745)" in lines[1] and "old_freq: (5220)" in lines[1]

    def test_scan_cache_count_with_debug(self):
        watcher, cw, lines = make_watcher(debug=logging.DEBUG)
        watcher.on_event("watching", "en0")
        watcher.on_event("scan_cache", "en0")
        assert lines[-1].endswith("scan: (78 BSSIDs found)")

    def test_scan_cache_quiet_by_default(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        watcher.on_event("scan_cache", "en0")
        assert len(lines) == 1 and "event: (watching)" in lines[0]

    def test_scan_cache_still_reports_state_change(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        cw.mode = 0  # disconnected, first noticed on a scan callback
        watcher.on_event("scan_cache", "en0")
        assert "event: (disconnected)" in lines[-1]
        assert not any("scan_cache_updated" in line for line in lines)

    def test_other_interface_ignored(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("bssid", "awdl0")
        assert lines == []

    def test_callback_errors_are_logged_not_raised(self, caplog):
        class Broken(FakeCWInterface):
            def powerOn(self):
                raise RuntimeError("xpc gone")

        watcher, cw, lines = make_watcher(Broken())
        watcher.on_event("power", "en0")
        assert "error handling CoreWLAN power event" in caplog.text

    def test_redacted_warns_once(self, monkeypatch):
        calls = []
        monkeypatch.setattr(macos, "warn_location_once", lambda: calls.append(1))
        watcher, cw, lines = make_watcher(FakeCWInterface(ssid=None, bssid_value=None))
        watcher.on_event("watching", "en0")
        cw.power = False
        watcher.on_event("power", "en0")
        assert lines[-1] == f"({MAC}), event: (power_off)"
        assert calls

    def test_log_event_line(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        watcher.on_log_event(LogEvent("deauth", "reason: (4 disassociated due to inactivity)"))
        assert lines[-1] == (
            f"({MAC}), bssid: (02:00:00:00:00:14), event: (deauth), "
            "reason: (4 disassociated due to inactivity)"
        )

    def test_log_event_without_detail_has_no_trailing_comma(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        watcher.on_log_event(LogEvent("system_sleep", ""))
        assert lines[-1] == (
            f"({MAC}), bssid: (02:00:00:00:00:14), event: (system_sleep)"
        )

    def test_roam_log_lines_are_single_line(self):
        watcher, cw, lines = make_watcher()
        watcher.on_event("watching", "en0")
        classifier = AirportdLogClassifier(Clock())
        for line in ROAM_LINES:
            for event in classifier.feed(line + "\n"):
                watcher.on_log_event(event)
        assert lines[-1] == (
            f"({MAC}), bssid: (02:00:00:00:00:14), event: (roam_requested), "
            "trigger: (best_connected_roam), roam_target_bssid: (any)"
        )
        assert all("\n" not in line and "->" not in line for line in lines)

    def test_start_and_stop(self, monkeypatch):
        from lswifi.backends import macos_events

        class Delegate:
            @classmethod
            def alloc(cls):
                return cls()

            def initWithWatcher_(self, watcher):
                self.watcher = watcher
                return self

        monkeypatch.setattr(macos_events, "_make_delegate_class", lambda: Delegate)
        watcher, cw, lines = make_watcher()
        watcher.client.refuse = {CW_EVENT_TYPES["mode"]}
        watcher.start(with_log_stream=False)
        assert isinstance(watcher.client.delegate, Delegate)
        assert sorted(watcher.client.started) == sorted(
            v for k, v in CW_EVENT_TYPES.items() if k != "mode"
        )
        assert "event: (watching)" in lines[0]
        watcher.stop()
        assert watcher.client.stopped and watcher.client.delegate is None

    def test_start_fails_when_everything_refused(self, monkeypatch):
        from lswifi.backends import macos_events

        monkeypatch.setattr(macos_events, "_make_delegate_class", lambda: _NullDelegate)
        watcher, cw, lines = make_watcher()
        watcher.client.refuse = set(CW_EVENT_TYPES.values())
        with pytest.raises(RuntimeError, match="refused every event"):
            watcher.start(with_log_stream=False)


class _NullDelegate:
    @classmethod
    def alloc(cls):
        return cls()

    def initWithWatcher_(self, watcher):
        return self


class TestAppDispatch:
    def test_watchevents_calls_backend(self, monkeypatch):
        from lswifi import app, appsetup

        called = []

        class Backend:
            name = "macos"
            platform_name = "macOS"
            supports_events = True

            def watch_events(self, args):
                called.append(args.event_watcher)

        args = appsetup.setup_parser().parse_args(["--watchevents"])
        with pytest.raises(SystemExit) as excinfo:
            app.lswifi().run(args, backend=Backend())
        assert called == [True]
        assert excinfo.value.code == 0


@pytest.mark.skipif(sys.platform != "darwin", reason="needs CoreWLAN")
def test_delegate_class_builds():
    pytest.importorskip("CoreWLAN")
    from lswifi.backends.macos_events import _make_delegate_class

    cls = _make_delegate_class()
    assert cls is _make_delegate_class()
    assert cls.alloc().initWithWatcher_(None) is not None
