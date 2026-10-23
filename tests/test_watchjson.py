"""--watchevents --json (NDJSON) for both backends; fakes only, any OS."""

import datetime
import io
import json
import logging
from types import SimpleNamespace

import pytest

from lswifi import watchjson
from lswifi.backends import macos
from lswifi.backends.base import InterfaceInfo
from lswifi.backends.macos_events import (
    AirportdLogClassifier,
    EventFormatter,
    EventLine,
    LinkState,
    LogEvent,
    MacOSEventWatcher,
)
from lswifi.schemas.out import OutObject
from lswifi.watchjson import (
    NDJSONWriter,
    dumps,
    event_record,
    freq_mhz,
    iso_timestamp,
    ssid_fields,
    to_number,
    watch_json_requested,
    windows_event_record,
)

MAC = "c0:c7:db:00:00:01"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def state(**kw):
    base = {
        "power": True,
        "connected": True,
        "ssid": "ExampleNet",
        "bssid": "02:00:00:00:00:14",
        "channel": 44,
        "band": "5 GHz",
        "width_mhz": 20,
        "frequency_mhz": 5220,
        "rssi": -44,
        "noise": -94,
        "tx_rate": 86.0,
        "mode": 1,
        "country_code": "US",
    }
    base.update(kw)
    return LinkState(**base)


# ---------------------------------------------------------------- shared helper


class TestHelper:
    def test_requested_needs_both_flags(self):
        assert watch_json_requested(SimpleNamespace(event_watcher=True, json="x.json"))
        assert not watch_json_requested(SimpleNamespace(event_watcher=True, json=None))
        assert not watch_json_requested(SimpleNamespace(event_watcher=False, json="x"))
        assert not watch_json_requested(SimpleNamespace())

    def test_timestamp_matches_scan_export_style(self):
        now = datetime.datetime(2026, 10, 22, 15, 20, 1, 123456)
        stamp = iso_timestamp(now)
        assert stamp == now.astimezone().isoformat(timespec="milliseconds")
        assert stamp.startswith("2026-10-22T15:20:01.123")
        assert stamp[-6] in "+-"  # local offset, not naive

    @pytest.mark.parametrize(
        "value,expected",
        [
            (-44, -44),
            ("-44", -44),
            (" 86.0 ", 86),
            (86.5, 86.5),
            ("", None),
            (None, None),
            (True, None),
            ("n/a", None),
            (float("nan"), None),
        ],
    )
    def test_to_number(self, value, expected):
        assert to_number(value) == expected

    def test_to_number_out_object(self):
        assert to_number(OutObject(value=-61)) == -61

    @pytest.mark.parametrize(
        "value,expected",
        [
            (5220, 5220),
            ("5220", 5220),
            ("5.220", 5220),
            ("2.412", 2412),
            ("5.955", 5955),
            (0, None),
            ("", None),
        ],
    )
    def test_freq_mhz(self, value, expected):
        assert freq_mhz(value) == expected

    def test_ssid_utf8_bytes(self):
        assert ssid_fields("café".encode()) == {"ssid": "café"}

    def test_ssid_not_utf8_adds_hex(self):
        fields = ssid_fields(b"ab\xff\xfe")
        assert fields == {"ssid": "ab\ufffd\ufffd", "ssid_hex": "6162fffe"}

    def test_ssid_empty_omitted(self):
        assert (
            ssid_fields(b"") == {} and ssid_fields("") == {} and ssid_fields(None) == {}
        )

    def test_record_order_and_omission(self):
        rec = event_record(
            "C0:C7:DB:00:00:01",
            "roamed",
            bssid="AA:BB:CC:DD:EE:FF",
            freq="5745",
            ssid="x",
            rssi="-60",
            channel=149,
            noise=None,
            band="",
            old_rssi=-44,
        )
        assert list(rec) == [
            "interface_mac",
            "event",
            "bssid",
            "freq_mhz",
            "ssid",
            "rssi",
            "channel",
            "old_rssi",
        ]
        assert rec["interface_mac"] == MAC and rec["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert rec["freq_mhz"] == 5745 and rec["rssi"] == -60

    def test_zero_bssid_omitted(self):
        assert "bssid" not in event_record(MAC, "x", bssid="00:00:00:00:00:00")

    def test_dumps_one_line_timestamp_first(self):
        line = dumps({"interface_mac": MAC, "event": "e", "ssid": "a\nb"}, "T")
        assert "\n" not in line
        assert list(json.loads(line)) == ["timestamp", "interface_mac", "event", "ssid"]
        assert json.loads(line)["ssid"] == "a\nb"

    def test_writer_flushes_each_line(self):
        class Stream(io.StringIO):
            flushes = 0

            def flush(self):
                self.flushes += 1

        stream = Stream()
        writer = NDJSONWriter(stream)
        writer.write(event_record(MAC, "a"))
        writer.write(event_record(MAC, "b"))
        lines = stream.getvalue().splitlines()
        assert [json.loads(line)["event"] for line in lines] == ["a", "b"]
        assert stream.flushes == 2

    def test_writer_broken_pipe_stops_quietly(self):
        class Closed:
            def write(self, _):
                raise BrokenPipeError

            def flush(self):
                pass

        writer = NDJSONWriter(Closed())
        writer.write(event_record(MAC, "a"))
        writer.write(event_record(MAC, "b"))
        assert writer.closed


# ---------------------------------------------------------------- macOS


@pytest.fixture
def formatter():
    fmt = EventFormatter(MAC, Clock())
    fmt.state_change(state())
    return fmt


class TestMacOSRecords:
    def test_watching_record(self):
        line = EventFormatter(MAC, Clock()).state_change(state())[0]
        assert isinstance(line, EventLine) and isinstance(line, str)
        assert line.record == {
            "interface_mac": MAC,
            "event": "watching",
            "bssid": "02:00:00:00:00:14",
            "freq_mhz": 5220,
            "ssid": "ExampleNet",
            "rssi": -44,
            "channel": 44,
            "width_mhz": 20,
            "band": "5 GHz",
            "noise": -94,
            "tx_rate_mbps": 86,
        }

    def test_roam_record_has_old_values(self, formatter):
        new = state(
            bssid="02:00:00:00:00:08",
            channel=149,
            frequency_mhz=5745,
            rssi=-60,
            width_mhz=80,
        )
        (line,) = formatter.state_change(new)
        rec = line.record
        assert rec["event"] == "roamed" and rec["bssid"] == "02:00:00:00:00:08"
        assert rec["freq_mhz"] == 5745 and rec["rssi"] == -60
        assert rec["channel"] == 149 and rec["width_mhz"] == 80
        assert rec["old_bssid"] == "02:00:00:00:00:14"
        assert rec["old_freq_mhz"] == 5220 and rec["old_rssi"] == -44
        assert rec["old_channel"] == 44 and rec["old_width_mhz"] == 20
        # text line is unchanged
        assert "old_freq: (5220)" in line and "old_channel: (44@20 5 GHz)" in line

    def test_disconnect_and_power(self, formatter):
        (line,) = formatter.state_change(state(connected=False, mode=0, bssid=""))
        assert line.record["event"] == "disconnected"
        assert line.record["bssid"] == "02:00:00:00:00:14"  # last known, as text
        (line,) = formatter.state_change(LinkState(power=False, country_code="US"))
        assert line.record == {"interface_mac": MAC, "event": "power_off"}

    def test_ssid_channel_mode_country(self, formatter):
        assert formatter.state_change(state(ssid="Other"))[0].record["old_ssid"] == (
            "ExampleNet"
        )
        rec = formatter.state_change(state(ssid="Other", channel=48))[0].record
        assert rec["event"] == "channel_change"
        assert rec["channel"] == 48 and rec["old_channel"] == 44
        rec = formatter.state_change(state(ssid="Other", channel=48, mode=2))[0].record
        assert (rec["mode"], rec["old_mode"]) == (2, 1)
        rec = formatter.state_change(
            state(ssid="Other", channel=48, mode=2, country_code="CA")
        )[0].record
        assert (rec["country_code"], rec["old_country_code"]) == ("CA", "US")

    def test_country_cleared_omits_key(self, formatter):
        rec = formatter.state_change(state(country_code=""))[0].record
        assert "country_code" not in rec and rec["old_country_code"] == "US"

    def test_signal_quality_and_scan(self, formatter):
        formatter.clock.now += 10
        rec = formatter.link_quality(state(rssi=-60, tx_rate=24.0))[0].record
        assert rec["event"] == "signal_quality_change"
        assert (rec["rssi"], rec["old_rssi"], rec["tx_rate_mbps"]) == (-60, -44, 24)
        rec = formatter.scan_cache(state(), 78)[0].record
        assert rec["scan_bssid_count"] == 78

    def test_redacted_flag(self):
        rec = (
            EventFormatter(MAC, Clock())
            .state_change(state(bssid="", ssid=""))[0]
            .record
        )
        assert rec["location_redacted"] is True
        assert "bssid" not in rec and "ssid" not in rec and rec["rssi"] == -44

    def test_non_utf8_ssid_from_bytes(self):
        rec = (
            EventFormatter(MAC, Clock())
            .state_change(state(ssid="a\ufffd", ssid_bytes=b"a\xff"))[0]
            .record
        )
        assert rec["ssid"] == "a\ufffd" and rec["ssid_hex"] == "61ff"

    def test_log_event_fields(self):
        classifier = AirportdLogClassifier()
        event = classifier.classify(
            "airportd: Received Deauth from 02:00:00:00:00:14 with Reason 4"
        )
        assert event.fields == {
            "from_bssid": "02:00:00:00:00:14",
            "reason_code": 4,
            "reason_text": "disassociated due to inactivity",
        }
        event = classifier.classify(
            "AUTO-JOIN: Updated join status uuid=X assoc=ok (272ms) auth=ok (948ms) "
            "linkup=ok (281ms) ipv4Primary=ok (12ms)"
        )
        assert event.fields == {
            "assoc_ms": 272,
            "auth_ms": 948,
            "linkup_ms": 281,
            "ipv4_primary_ms": 12,
        }


class FakeCW:
    def powerOn(self):
        return True

    def interfaceMode(self):
        return 1

    def ssidData(self):
        return b"ExampleNet"

    def bssid(self):
        return "02:00:00:00:00:14"

    def wlanChannel(self):
        return SimpleNamespace(
            channelNumber=lambda: 44,
            channelBand=lambda: macos.CW_CHANNEL_BAND_5GHZ,
            channelWidth=lambda: 1,
        )

    def rssiValue(self):
        return -44

    def noiseMeasurement(self):
        return -94

    def transmitRate(self):
        return 86.0

    def countryCode(self):
        return "US"

    def cachedScanResults(self):
        return [object()] * 3


def make_watcher(monkeypatch, syslog=None, debug=logging.DEBUG):
    stream = io.StringIO()
    monkeypatch.setattr(watchjson, "_writer", NDJSONWriter(stream))
    sent = []
    import lswifi.slog

    monkeypatch.setattr(lswifi.slog, "message", lambda msg, level: sent.append(msg))
    info = InterfaceInfo(
        connection_name="en0",
        description="Wi-Fi (en0)",
        guid_string="",
        mac=MAC,
        state_string="connected",
        native=FakeCW(),
    )
    args = SimpleNamespace(
        event_watcher=True, json="lswifi_x.json", syslog=syslog, debug=debug
    )
    watcher = MacOSEventWatcher(SimpleNamespace(), [info], args, clock=Clock())
    return watcher, stream, sent


class TestMacOSWatcherJSON:
    def test_ndjson_on_stdout_not_log(self, monkeypatch, caplog):
        watcher, stream, _ = make_watcher(monkeypatch)
        with caplog.at_level(logging.INFO):
            watcher.on_event("watching", "en0")
            watcher.on_event("scan_cache", "en0")
            watcher.on_log_event(
                LogEvent(
                    "deauth", "reason: (4 x)", {"reason_code": 4, "reason_text": "x"}
                )
            )
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        assert [r["event"] for r in records] == [
            "watching",
            "scan_cache_updated",
            "deauth",
        ]
        assert records[1]["scan_bssid_count"] == 3
        assert (
            records[2]["reason_code"] == 4
            and records[2]["bssid"] == "02:00:00:00:00:14"
        )
        assert all(r["timestamp"][-6] in "+-" for r in records)
        assert "event: (" not in caplog.text

    def test_scan_cache_quiet_without_debug(self, monkeypatch):
        watcher, stream, _ = make_watcher(monkeypatch, debug=logging.INFO)
        watcher.on_event("watching", "en0")
        watcher.on_event("scan_cache", "en0")
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        assert [r["event"] for r in records] == ["watching"]

    def test_roam_and_wake_records(self, monkeypatch):
        watcher, stream, _ = make_watcher(monkeypatch)
        watcher.on_event("watching", "en0")
        classifier = AirportdLogClassifier()
        lines = [
            "2026-10-22 20:12:38.519 Df airportd[423:1] Roam: <airport[423]> "
            "-[CWXPCInterfaceContext __triggerRoamWithInterface:]: BEST CONNECTED ROAM triggered",
            "2026-10-22 20:12:38.519 Df airportd[423:1] Roam: <airport[423]> "
            "-[CWXPCInterfaceContext __triggerRoamWithInterface:]: Requesting Roam : {",
            "    BSSID = {length = 6, bytes = 0xffffffffffff};",
            "}",
            "2026-10-22 20:13:34.339 Df airportd[423:1] AutoJoin: <airport[423]> "
            "airportdProcessWake: Received dark wake event for en0",
        ]
        for line in lines:
            for event in classifier.feed(line + "\n"):
                watcher.on_log_event(event)
        out = stream.getvalue().splitlines()
        records = [json.loads(line) for line in out]
        assert records[1] == {
            "timestamp": records[1]["timestamp"],
            "interface_mac": MAC,
            "event": "roam_requested",
            "bssid": "02:00:00:00:00:14",
            "trigger": "best_connected_roam",
            "roam_target_bssid": "any",
        }
        assert records[2]["event"] == "system_wake" and records[2]["wake"] == "dark"

    def test_syslog_still_gets_text(self, monkeypatch):
        watcher, stream, sent = make_watcher(monkeypatch, syslog="192.0.2.1")
        watcher.on_event("watching", "en0")
        assert sent and sent[0].startswith(
            f"({MAC}), bssid: (02:00:00:00:00:14), freq: (5220)"
        )
        assert json.loads(stream.getvalue())["event"] == "watching"

    def test_text_mode_unchanged(self, monkeypatch, caplog):
        watcher, stream, _ = make_watcher(monkeypatch)
        watcher.args.json = None
        watcher.json_writer = None
        with caplog.at_level(logging.INFO):
            watcher.on_event("watching", "en0")
        assert stream.getvalue() == ""
        assert (
            f"({MAC}), bssid: (02:00:00:00:00:14), freq: (5220), ssid: (ExampleNet)"
            in caplog.text
        )


# ---------------------------------------------------------------- Windows


def fake_bss(freq="5.220", rssi=-61, ssid="ExampleNet", channel="44"):
    """Shaped like lswifi.elements.WirelessNetworkBss after IE parsing"""
    return SimpleNamespace(
        bssid=OutObject(value="02:00:00:00:00:14"),
        channel_frequency=OutObject(value=freq),
        rssi=OutObject(value=rssi),
        ssid=OutObject(value=ssid),
        channel_number=OutObject(value=channel),
    )


class TestWindowsRecords:
    def test_connected_bss(self):
        rec = windows_event_record(
            MAC, " signal_quality_change", "02:00:00:00:00:14", fake_bss()
        )
        assert rec == {
            "interface_mac": MAC,
            "event": "signal_quality_change",
            "bssid": "02:00:00:00:00:14",
            "freq_mhz": 5220,
            "ssid": "ExampleNet",
            "rssi": -61,
            "channel": 44,
        }

    def test_scan_complete_count(self):
        rec = windows_event_record(
            MAC, "scan_complete", "02:00:00:00:00:14", fake_bss(), 42
        )
        assert rec["scan_bssid_count"] == 42

    def test_disconnected(self):
        rec = windows_event_record(MAC, "scan_complete", "00:00:00:00:00:00", None, 7)
        assert rec == {
            "interface_mac": MAC,
            "event": "scan_complete",
            "scan_bssid_count": 7,
        }
        assert windows_event_record(MAC, "disconnected") == {
            "interface_mac": MAC,
            "event": "disconnected",
        }

    def test_bss_not_found_in_list(self):
        rec = windows_event_record(MAC, "connected", "02:00:00:00:00:14", None)
        assert set(rec) == {"interface_mac", "event", "bssid"}

    def test_six_ghz(self):
        rec = windows_event_record(
            MAC, "roaming_end", "x", fake_bss(freq="5.955", channel="1")
        )
        assert rec["freq_mhz"] == 5955 and rec["channel"] == 1


class TestWindowsClientEmit:
    """lswifi.client.Client.emit_watch_event without a WLAN handle"""

    def make(self, monkeypatch, json_arg, syslog=None):
        from lswifi import client

        stream = io.StringIO()
        monkeypatch.setattr(watchjson, "_writer", NDJSONWriter(stream))
        sent = []
        monkeypatch.setattr(client, "syslog", lambda msg, level: sent.append(msg))
        fake = SimpleNamespace(
            mac=MAC,
            args=SimpleNamespace(event_watcher=True, json=json_arg, syslog=syslog),
            log=logging.getLogger("lswifi.client"),
        )
        return client.Client.emit_watch_event, fake, stream, sent

    def test_text_mode_logs_msg_exactly(self, monkeypatch, caplog):
        emit, fake, stream, sent = self.make(monkeypatch, None, "192.0.2.1")
        msg = f"({MAC}), bssid: (02:00:00:00:00:14), event: (roaming_start)"
        with caplog.at_level(logging.INFO, logger="lswifi.client"):
            emit(fake, msg, "roaming_start", "02:00:00:00:00:14")
        assert [r.getMessage() for r in caplog.records] == [msg]
        assert sent == [msg] and stream.getvalue() == ""

    def test_json_mode_writes_record_and_syslogs_text(self, monkeypatch, caplog):
        emit, fake, stream, sent = self.make(monkeypatch, "lswifi_x.json", "192.0.2.1")
        msg = "text line"
        with caplog.at_level(logging.INFO, logger="lswifi.client"):
            emit(fake, msg, "scan_complete", "02:00:00:00:00:14", fake_bss(), 12)
        rec = json.loads(stream.getvalue())
        assert rec["event"] == "scan_complete" and rec["scan_bssid_count"] == 12
        assert rec["freq_mhz"] == 5220 and rec["rssi"] == -61
        assert caplog.records == [] and sent == [msg]


# ---------------------------------------------------------------- CLI


def test_watchevents_json_routes_and_warns_for_explicit_file(
    tmp_path, monkeypatch, caplog
):
    from lswifi import app, appsetup

    monkeypatch.chdir(tmp_path)
    seen = []

    class Backend:
        name = "fake"
        supports_events = True

        def watch_events(self, args):
            seen.append(watch_json_requested(args))

    for argv, warned in (
        (["--watchevents", "--json"], False),
        (["--watchevents", "--json", "out.json"], True),
    ):
        caplog.clear()
        args = appsetup.setup_parser().parse_args(argv)
        with pytest.raises(SystemExit):
            app.lswifi().run(args, backend=Backend())
        assert ("ignoring out.json" in caplog.text) is warned
        assert not (tmp_path / "out.json").exists()
    assert seen == [True, True]
