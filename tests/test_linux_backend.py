# -*- encoding: utf-8

"""Linux (nl80211) backend tests with synthetic netlink messages. Runs on any OS."""

import errno
import json
import struct
import sys

import pytest

from lswifi import appsetup
from lswifi.backends import nl80211 as nl
from lswifi.backends.base import BackendError, BackendUnavailableError, InterfaceInfo
from lswifi.backends.linux import (
    PERMISSION_HELP,
    LinkInfo,
    LinuxBackend,
    LinuxInterface,
    LinuxScanSession,
    Sysfs,
    bss_to_record,
    interface_from_attrs,
    ssid_from_ies,
    station_to_link,
)
from lswifi.backends.linux_events import LinkFormatter, LinuxEventWatcher
from lswifi.elements import WirelessNetworkBss

FAMILY = 0x1C
GROUPS = {"config": 5, "scan": 6, "regulatory": 7, "mlme": 8}


def mac(last: int) -> bytes:
    return bytes([0x02, 0, 0, 0, 0, last])


def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


# RSN: CCMP-128 group and pairwise, SAE + PSK, MFP capable
RSN = ie(
    48,
    struct.pack("<H", 1)
    + b"\x00\x0f\xac\x04"
    + struct.pack("<H", 1)
    + b"\x00\x0f\xac\x04"
    + struct.pack("<H", 2)
    + b"\x00\x0f\xac\x08"
    + b"\x00\x0f\xac\x02"
    + struct.pack("<H", 0x0080),
)
RATES = ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))


def ies_for(ssid: bytes, channel: int | None = None) -> bytes:
    body = ie(0, ssid) + RATES
    if channel is not None:
        body += ie(3, bytes([channel]))
    return body + RSN


def bss_attrs(
    last: int,
    freq: int,
    ssid: bytes = b"ExampleNet",
    mbm: int | None = -5500,
    status: int | None = None,
    presp: bool = False,
    beacon_only: bool = False,
    channel: int | None = None,
) -> bytes:
    ies = ies_for(ssid, channel)
    attrs = [
        nl.pack_attr(nl.BSS_BSSID, mac(last)),
        nl.attr_u32(nl.BSS_FREQUENCY, freq),
        nl.attr_u64(nl.BSS_TSF, 212_000_000),
        nl.attr_u16(nl.BSS_BEACON_INTERVAL, 100),
        nl.attr_u16(nl.BSS_CAPABILITY, 0x0411),
        nl.attr_s32(nl.BSS_SIGNAL_MBM, mbm)
        if mbm is not None
        else nl.attr_u8(nl.BSS_SIGNAL_UNSPEC, 60),
        nl.attr_u32(nl.BSS_SEEN_MS_AGO, 1200),
        nl.attr_u32(nl.BSS_CHAN_WIDTH, 0),
    ]
    if beacon_only:
        attrs.append(nl.pack_attr(nl.BSS_BEACON_IES, ies))
    else:
        attrs.append(nl.pack_attr(nl.BSS_INFORMATION_ELEMENTS, ies))
        attrs.append(nl.pack_attr(nl.BSS_BEACON_IES, b"\x00\x00"))
    if presp:
        attrs.append(nl.attr_flag(nl.BSS_PRESP_DATA))
    if status is not None:
        attrs.append(nl.attr_u32(nl.BSS_STATUS, status))
    return b"".join(attrs)


def iface_attrs(
    ifindex, name, iftype=nl.IFTYPE_STATION, ssid=b"", freq=None, last=0x10
):
    attrs = [
        nl.attr_u32(nl.ATTR_IFINDEX, ifindex),
        nl.attr_str(nl.ATTR_IFNAME, name),
        nl.attr_u32(nl.ATTR_WIPHY, 0),
        nl.attr_u32(nl.ATTR_IFTYPE, iftype),
        nl.pack_attr(nl.ATTR_MAC, mac(last)),
        nl.attr_u64(nl.ATTR_WDEV, 1),
    ]
    if ssid:
        attrs.append(nl.pack_attr(nl.ATTR_SSID, ssid))
    if freq:
        attrs += [
            nl.attr_u32(nl.ATTR_WIPHY_FREQ, freq),
            nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 3),
            nl.attr_u32(nl.ATTR_WIPHY_TX_POWER_LEVEL, 2000),
        ]
    return b"".join(attrs)


def station_attrs(last: int, signal: int, rate_units: int) -> bytes:
    tx = nl.pack_nested(
        nl.STA_INFO_TX_BITRATE, [nl.attr_u32(nl.RATE_INFO_BITRATE32, rate_units)]
    )
    info = nl.pack_nested(
        nl.ATTR_STA_INFO,
        [nl.pack_attr(nl.STA_INFO_SIGNAL, struct.pack("=b", signal)), tx],
    )
    return nl.pack_attr(nl.ATTR_MAC, mac(last)) + info


def family_reply(seq: int) -> bytes:
    groups = nl.pack_nested(
        nl.CTRL_ATTR_MCAST_GROUPS,
        [
            nl.pack_nested(
                index + 1,
                [
                    nl.attr_str(nl.CTRL_ATTR_MCAST_GRP_NAME, name),
                    nl.attr_u32(nl.CTRL_ATTR_MCAST_GRP_ID, gid),
                ],
            )
            for index, (name, gid) in enumerate(GROUPS.items())
        ],
    )
    attrs = (
        nl.attr_str(nl.CTRL_ATTR_FAMILY_NAME, "nl80211")
        + nl.attr_u16(nl.CTRL_ATTR_FAMILY_ID, FAMILY)
        + groups
    )
    return nl.build_message(
        nl.GENL_ID_CTRL, nl.CTRL_CMD_NEWFAMILY, attrs, flags=0, seq=seq
    )


def event(cmd: int, attrs: bytes) -> bytes:
    return nl.build_message(FAMILY, cmd, attrs, flags=0, seq=0)


class FakeKernel:
    """Answers nl80211 requests from canned attributes; one per test"""

    def __init__(self):
        self.interfaces = [iface_attrs(5, "wlan1")]
        self.bss = [bss_attrs(0x01, 2412, channel=1)]
        self.stations: list[bytes] = []
        self.trigger_error = 0
        self.scan_event = nl.CMD_NEW_SCAN_RESULTS
        self.alpha2 = "US"
        self.bands = [0, 1]
        self.sockets: list[FakeSocket] = []
        self.sent: list[nl.GenlMessage] = []

    def socket(self) -> "FakeSocket":
        sock = FakeSocket(self)
        self.sockets.append(sock)
        return sock

    def netlink(self) -> nl.GenericNetlink:
        return nl.GenericNetlink(self.socket())

    def broadcast(self, group: str, data: bytes) -> None:
        for sock in self.sockets:
            if GROUPS[group] in sock.groups and not sock.closed:
                sock.queue.append(data)

    def answer(self, sock: "FakeSocket", data: bytes) -> list[bytes]:
        (raw,) = list(nl.iter_messages(data))
        msg = nl.to_genl(raw)
        self.sent.append(msg)
        seq = raw.seq
        if raw.type == nl.GENL_ID_CTRL:
            return [family_reply(seq), nl.build_error(seq, 0)]
        dump = raw.flags & nl.NLM_F_DUMP == nl.NLM_F_DUMP

        def multi(cmd, items):
            return [
                nl.build_message(FAMILY, cmd, a, flags=nl.NLM_F_MULTI, seq=seq)
                for a in items
            ] + [nl.build_done(seq)]

        if msg.cmd == nl.CMD_GET_INTERFACE:
            items = self.interfaces
            if not dump:
                ifindex = nl.get_uint(msg.attrs, nl.ATTR_IFINDEX)
                items = [
                    a
                    for a in items
                    if nl.get_uint(nl.parse_attrs(a), nl.ATTR_IFINDEX) == ifindex
                ]
                return [
                    nl.build_message(
                        FAMILY, nl.CMD_NEW_INTERFACE, items[0], flags=0, seq=seq
                    ),
                    nl.build_error(seq, 0),
                ]
            return multi(nl.CMD_NEW_INTERFACE, items)
        if msg.cmd == nl.CMD_GET_SCAN:
            return multi(
                nl.CMD_NEW_SCAN_RESULTS,
                [
                    nl.pack_nested(nl.ATTR_BSS, [b]) + nl.attr_u32(nl.ATTR_IFINDEX, 5)
                    for b in self.bss
                ],
            )
        if msg.cmd == nl.CMD_GET_WIPHY:
            bands = [nl.pack_attr(band, b"") for band in self.bands]
            return multi(
                3,  # NL80211_CMD_NEW_WIPHY
                [
                    nl.attr_u32(nl.ATTR_WIPHY, 0)
                    + nl.pack_nested(nl.ATTR_WIPHY_BANDS, bands)
                ],
            )
        if msg.cmd == nl.CMD_GET_STATION:
            return multi(nl.CMD_NEW_STATION, self.stations)
        if msg.cmd == nl.CMD_GET_REG:
            return [
                nl.build_message(
                    FAMILY,
                    nl.CMD_GET_REG,
                    nl.attr_str(nl.ATTR_REG_ALPHA2, self.alpha2),
                    flags=0,
                    seq=seq,
                ),
                nl.build_error(seq, 0),
            ]
        if msg.cmd == nl.CMD_TRIGGER_SCAN:
            if self.trigger_error:
                return [nl.build_error(seq, -self.trigger_error)]
            ifindex = nl.get_uint(msg.attrs, nl.ATTR_IFINDEX)
            if self.scan_event:
                self.broadcast(
                    "scan",
                    event(self.scan_event, nl.attr_u32(nl.ATTR_IFINDEX, ifindex)),
                )
            return [nl.build_error(seq, 0)]
        return [nl.build_error(seq, -errno.EOPNOTSUPP)]


class FakeSocket:
    def __init__(self, kernel: FakeKernel):
        self.kernel = kernel
        self.queue: list[bytes] = []
        self.groups: set[int] = set()
        self.closed = False

    def send(self, data: bytes) -> int:
        self.queue.extend(self.kernel.answer(self, data))
        return len(data)

    def recv(self, bufsize: int) -> bytes:
        # the kernel packs several messages into one datagram
        data, self.queue = b"".join(self.queue), []
        return data

    def pending(self) -> bool:
        return bool(self.queue)

    def setsockopt(self, level, option, value) -> None:
        assert (level, option) == (nl.SOL_NETLINK, nl.NETLINK_ADD_MEMBERSHIP)
        self.groups.add(value)

    def fileno(self) -> int:
        return -1

    def close(self) -> None:
        self.closed = True


class FakeSysfs(Sysfs):
    def __init__(self, up=True):
        super().__init__("/nonexistent")
        self.up = up

    def is_up(self, name):
        return self.up

    def driver(self, name):
        return "mt7921u"

    def bus_info(self, name):
        return ("USB", "0e8d:7961 at 1-1:1.0")


@pytest.fixture
def kernel():
    return FakeKernel()


@pytest.fixture
def backend(kernel):
    return LinuxBackend(netlink=kernel.netlink, sysfs=FakeSysfs(), scan_timeout=0.2)


@pytest.fixture(autouse=True)
def reset_warning(monkeypatch):
    from lswifi.backends import linux

    monkeypatch.setattr(linux, "_permission_warned", False)


def parse(argv):
    return appsetup.setup_parser().parse_args(argv)


class TestNetlink:
    def test_attr_round_trip_and_alignment(self):
        data = (
            nl.attr_u8(1, 7)
            + nl.attr_str(2, "wlan0")
            + nl.attr_flag(3)
            + nl.attr_u64(4, 2**40)
        )
        assert len(data) % 4 == 0
        attrs = nl.parse_attrs(data)
        assert nl.get_uint(attrs, 1) == 7
        assert nl.get_str(attrs, 2) == "wlan0"
        assert attrs[3] == b""
        assert nl.get_uint(attrs, 4) == 2**40

    def test_nested_flag_is_masked(self):
        data = nl.pack_nested(9, [nl.attr_u32(1, 5)])
        ((kind, payload),) = list(nl.iter_attrs(data))
        assert kind == 9
        assert nl.get_uint(nl.parse_attrs(payload), 1) == 5

    def test_truncated_attr_stops(self):
        data = nl.attr_u32(1, 5) + struct.pack("=HH", 40, 2) + b"\0" * 4
        assert list(nl.parse_attrs(data)) == [1]

    def test_signed(self):
        assert nl.get_int(nl.parse_attrs(nl.attr_s32(7, -6100)), 7) == -6100

    def test_family_and_groups(self, kernel):
        sock = kernel.netlink()
        assert sock.family_id == FAMILY
        assert sock.groups["mlme"] == 8
        assert sock.groups["scan"] == 6

    def test_error_reply_raises(self, kernel):
        sock = kernel.netlink()
        with pytest.raises(nl.NetlinkError) as excinfo:
            sock.request(250)
        assert excinfo.value.errno == errno.EOPNOTSUPP

    def test_dump_error_in_done_raises(self):
        class Sock(FakeSocket):
            def send(self, data):
                (raw,) = list(nl.iter_messages(data))
                if raw.type == nl.GENL_ID_CTRL:
                    return super().send(data)
                payload = struct.pack("=i", -errno.ENOBUFS)
                self.queue.append(
                    nl.NLMSG_HDR.pack(20, nl.NLMSG_DONE, nl.NLM_F_MULTI, raw.seq, 0)
                    + payload
                )
                return len(data)

        sock = nl.GenericNetlink(Sock(FakeKernel()))
        with pytest.raises(nl.NetlinkError):
            sock.request(nl.CMD_GET_SCAN, dump=True)

    def test_stale_replies_are_skipped(self, kernel):
        sock = kernel.netlink()
        fake = sock.sock
        fake.queue.append(
            nl.build_message(FAMILY, nl.CMD_NEW_INTERFACE, b"", flags=0, seq=1)
        )
        assert len(sock.request(nl.CMD_GET_INTERFACE, dump=True)) == 1

    def test_unknown_group(self, kernel):
        with pytest.raises(OSError):
            kernel.netlink().join("nope")

    def test_open_socket_without_af_netlink(self, monkeypatch):
        import socket

        monkeypatch.delattr(socket, "AF_NETLINK", raising=False)
        with pytest.raises(OSError):
            nl.open_socket()


class TestBssRecord:
    def test_mapping(self):
        record = bss_to_record(
            nl.parse_attrs(
                bss_attrs(0x01, 2412, status=nl.BSS_STATUS_ASSOCIATED, channel=1)
            )
        )
        assert record.ssid == b"ExampleNet"
        assert record.bssid == "02:00:00:00:00:01"
        assert record.frequency_mhz == 2412
        assert record.rssi_dbm == -55
        assert record.tsf == 212_000_000
        assert record.capability == 0x0411
        assert record.beacon_interval_tu == 100
        assert record.connected is True
        assert record.ie_source == "beacon"
        assert record.channel_width_mhz == 20
        assert record.seen_ms_ago == 1200
        assert record.ies.startswith(b"\x00\x0aExampleNet")
        assert record.rate_set is None and record.raw is None

    def test_probe_response_and_beacon_fallback(self):
        presp = bss_to_record(nl.parse_attrs(bss_attrs(0x02, 5180, presp=True)))
        assert presp.ie_source == "probe_response"
        beacon = bss_to_record(nl.parse_attrs(bss_attrs(0x03, 5180, beacon_only=True)))
        assert beacon.ie_source == "beacon"
        assert beacon.ssid == b"ExampleNet"

    def test_rounding_and_not_connected(self):
        record = bss_to_record(
            nl.parse_attrs(
                bss_attrs(0x04, 5975, mbm=-6150, status=nl.BSS_STATUS_AUTHENTICATED)
            )
        )
        assert record.rssi_dbm == -62
        assert record.connected is False

    def test_ibss(self):
        attrs = nl.parse_attrs(bss_attrs(0x05, 2437))
        attrs[nl.BSS_CAPABILITY] = struct.pack("=H", 0x0002)
        assert bss_to_record(attrs).bss_type == "Independent"

    def test_ssid_from_ies(self):
        assert ssid_from_ies(ie(3, b"\x01") + ie(0, b"ExampleNet-6")) == b"ExampleNet-6"
        assert ssid_from_ies(b"\x00\x09Ex") == b""
        assert ssid_from_ies(b"") == b""

    @pytest.mark.parametrize(
        "freq, channel", [(2412, "1"), (5180, "36"), (5975, "5"), (6115, "33")]
    )
    def test_parsed_by_ie_parsers(self, freq, channel):
        record = bss_to_record(nl.parse_attrs(bss_attrs(0x06, freq)))
        bss = WirelessNetworkBss(record)
        assert str(bss.ssid) == "ExampleNet"
        assert str(bss.bssid).startswith("02:00:00:00:00:06")
        assert str(bss.channel_number) == channel
        assert str(bss.rssi) == "-55"
        assert "SAE" in str(bss.security) and "CCMP" in str(bss.security)


class TestInterfaces:
    def test_list_skips_monitor(self, kernel, backend):
        kernel.interfaces = [
            iface_attrs(6, "wlanpi0", iftype=nl.IFTYPE_MONITOR, last=0x11),
            iface_attrs(5, "wlan1", last=0x12),
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13),
            nl.attr_u32(nl.ATTR_IFTYPE, 10),  # P2P device: no netdev
        ]
        infos = backend.list_interfaces()
        assert [i.connection_name for i in infos] == ["wlan0", "wlan1"]
        wlan0, wlan1 = infos
        assert wlan0.state_string == "connected"
        assert wlan1.state_string == "disconnected"
        assert wlan0.description == "mt7921u (phy0)"
        assert wlan0.mac == "02:00:00:00:00:13"
        assert wlan0.guid_string == ""
        assert wlan0.native.width_mhz == 80

    def test_down(self, kernel):
        backend = LinuxBackend(netlink=kernel.netlink, sysfs=FakeSysfs(up=False))
        assert backend.list_interfaces()[0].state_string == "down"

    def test_interface_from_attrs_without_ifindex(self):
        assert interface_from_attrs({}) is None

    def test_station(self):
        assert station_to_link(nl.parse_attrs(station_attrs(0x21, -48, 8645))) == (
            "02:00:00:00:00:21",
            -48,
            864.5,
        )

    def test_unavailable(self):
        def broken():
            raise OSError(errno.ENOENT, "no nl80211")

        with pytest.raises(BackendUnavailableError, match="nl80211"):
            LinuxBackend(netlink=broken)

    def test_sysfs(self, tmp_path):
        net = tmp_path / "net"
        (net / "wlan1").mkdir(parents=True)
        (net / "wlan1" / "flags").write_text("0x1003\n")
        (net / "wlan2").mkdir()
        (net / "wlan2" / "flags").write_text("0x1002\n")
        sysfs = Sysfs(str(net))
        assert sysfs.is_up("wlan1") is True
        assert sysfs.is_up("wlan2") is False
        assert sysfs.is_up("wlan3") is None
        assert sysfs.driver("wlan1") is None
        assert sysfs.bus_info("wlan1") == (None, None)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="sysfs paths need ':' and symlinks"
    )
    def test_sysfs_usb(self, tmp_path):
        usb = tmp_path / "devices" / "1-1"
        intf = usb / "1-1:1.0"
        (intf / "driver").parent.mkdir(parents=True)
        (tmp_path / "bus" / "usb").mkdir(parents=True)
        (tmp_path / "drivers" / "mt7921u").mkdir(parents=True)
        (intf / "subsystem").symlink_to(tmp_path / "bus" / "usb")
        (intf / "driver").symlink_to(tmp_path / "drivers" / "mt7921u")
        (usb / "idVendor").write_text("0e8d\n")
        (usb / "idProduct").write_text("7961\n")
        (tmp_path / "net" / "wlan1").mkdir(parents=True)
        (tmp_path / "net" / "wlan1" / "device").symlink_to(intf)
        sysfs = Sysfs(str(tmp_path / "net"))
        assert sysfs.driver("wlan1") == "mt7921u"
        assert sysfs.bus_info("wlan1") == ("USB", "0e8d:7961 at 1-1:1.0")


class TestScan:
    def iface(self, backend):
        return backend.list_interfaces()[0]

    def test_triggered_scan(self, kernel, backend, caplog):
        kernel.bss = [
            bss_attrs(0x01, 2412, channel=1),
            bss_attrs(0x02, 5180),
            bss_attrs(0x03, 5975),
        ]
        records = backend.scan(self.iface(backend))
        assert [r.frequency_mhz for r in records] == [2412, 5180, 5975]
        trigger = [m for m in kernel.sent if m.cmd == nl.CMD_TRIGGER_SCAN][0]
        assert nl.get_uint(trigger.attrs, nl.ATTR_IFINDEX) == 5
        ssids = nl.parse_attrs(trigger.attrs[nl.ATTR_SCAN_SSIDS])
        assert ssids == {1: b""}  # one wildcard SSID: active scan
        assert PERMISSION_HELP not in caplog.text

    def test_unprivileged_falls_back_to_cache(self, kernel, backend, caplog):
        kernel.trigger_error = errno.EPERM
        records = backend.scan(self.iface(backend))
        assert len(records) == 1
        assert caplog.text.count("CAP_NET_ADMIN") == 1
        backend.scan(self.iface(backend))
        assert caplog.text.count("CAP_NET_ADMIN") == 1  # warned once

    def test_down_unprivileged(self, kernel, backend):
        kernel.trigger_error = errno.EPERM
        backend.sysfs.up = False
        with pytest.raises(BackendError, match="is down"):
            backend.scan(self.iface(backend))

    def scan_flags(self, kernel):
        (trigger,) = [m for m in kernel.sent if m.cmd == nl.CMD_TRIGGER_SCAN]
        return nl.get_uint(trigger.attrs, nl.ATTR_SCAN_FLAGS)

    def test_colocated_6ghz_when_wiphy_has_6ghz(self, kernel, backend):
        kernel.bands = [0, 1, nl.BAND_6GHZ]
        backend.scan(self.iface(backend))
        assert self.scan_flags(kernel) == nl.SCAN_FLAG_COLOCATED_6GHZ

    def test_no_6ghz_flag_without_6ghz(self, kernel, backend):
        backend.scan(self.iface(backend))
        assert self.scan_flags(kernel) is None

    def test_wiphy_bands_cached(self, kernel, backend):
        backend.scan(self.iface(backend))
        backend.scan(self.iface(backend))
        assert [m.cmd for m in kernel.sent].count(nl.CMD_GET_WIPHY) == 1

    def test_unprivileged_empty_cache(self, kernel, backend, caplog):
        kernel.trigger_error = errno.EPERM
        kernel.bss = []
        assert backend.scan(self.iface(backend)) == []
        assert "no cached scan results" in caplog.text
        assert "nmcli device wifi rescan" in caplog.text

    def test_busy_waits_for_running_scan(self, kernel, backend, caplog):
        kernel.trigger_error = errno.EBUSY
        records = backend.scan(self.iface(backend))
        assert len(records) == 1
        assert "did not finish" in caplog.text

    def test_aborted(self, kernel, backend, caplog):
        kernel.scan_event = nl.CMD_SCAN_ABORTED
        assert len(backend.scan(self.iface(backend))) == 1
        assert "aborted" in caplog.text

    def test_other_interface_results_do_not_count(self, kernel, backend, caplog):
        kernel.scan_event = 0
        iface = self.iface(backend)
        kernel.broadcast(
            "scan", event(nl.CMD_NEW_SCAN_RESULTS, nl.attr_u32(nl.ATTR_IFINDEX, 99))
        )
        backend.scan(iface)
        assert "did not finish" in caplog.text

    def test_down_interface(self, kernel, backend):
        kernel.trigger_error = errno.ENETDOWN
        with pytest.raises(BackendError, match="ip link set wlan1 up"):
            backend.scan(self.iface(backend))

    def test_session_logs_backend_error(self, kernel, backend, caplog):
        import asyncio

        kernel.trigger_error = errno.ENETDOWN
        session = backend.open_session(parse([]), self.iface(backend))
        assert isinstance(session, LinuxScanSession)
        asyncio.run(session.scan())
        assert session.data is None and session.scan_finished
        assert "is down" in caplog.text

    def test_session_wraps_records(self, kernel, backend):
        import asyncio

        session = backend.open_session(parse([]), self.iface(backend))
        asyncio.run(session.scan())
        (bss,) = session.data
        assert str(bss.ssid) == "ExampleNet"


class TestInterfaceInfo:
    def connected(self, kernel, backend):
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
        ]
        kernel.stations = [station_attrs(0x21, -48, 8645)]
        return backend.list_interfaces()[0]

    def test_text(self, kernel, backend):
        out = backend.interface_info(
            parse(["--get-interfaces"]), self.connected(kernel, backend)
        )
        assert "Interface: wlan0 is connected" in out
        assert "SSID: ExampleNet" in out
        assert "BSSID: 02:00:00:00:00:21" in out
        assert "Channel: 36" in out
        assert "Band: 5 GHz" in out
        assert "Width: 80 MHz" in out
        assert "RSSI: -48 dBm" in out
        assert "Transmit (Tx) Rate: 864.5 Mbps" in out
        assert "Transmit Power: 20 dBm" in out
        assert "Country Code: US" in out
        assert "Bus: USB 0e8d:7961" in out

    def test_ap_and_channel(self, kernel, backend):
        iface = self.connected(kernel, backend)
        assert backend.interface_info(parse(["-ap"]), iface) == (
            "INTERFACE: wlan0, MAC: 02:00:00:00:00:13, BSSID: 02:00:00:00:00:21"
        )
        assert backend.interface_info(parse(["-channel", "-raw"]), iface) == "36"

    def test_down_hides_stale_channel(self, kernel, backend):
        iface = self.connected(kernel, backend)
        backend.sysfs.up = False
        assert backend.link(iface.native).channel is None
        assert backend.interface_info(parse(["-channel", "-raw"]), iface) == "None"

    def test_json(self, kernel, backend):
        out = backend.interface_info(
            parse(["--get-interfaces", "--json"]), self.connected(kernel, backend)
        )
        info = json.loads(out)
        assert info["bssid"] == "02:00:00:00:00:21"
        assert info["channel"] == 36
        assert info["state"] == "connected"

    def test_disconnected(self, kernel, backend):
        out = backend.interface_info(
            parse(["--get-interfaces"]), backend.list_interfaces()[0]
        )
        assert "is disconnected" in out
        assert "SSID" not in out

    def test_supported(self, kernel, backend):
        out = backend.interface_info(
            parse(["--get-interfaces", "--supported"]), backend.list_interfaces()[0]
        )
        assert "unsupported on Linux" in out


class TestEvents:
    def watcher(self, kernel, backend, argv=("--watchevents",)):
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
        ]
        kernel.stations = [station_attrs(0x21, -48, 8645)]
        lines: list = []
        watcher = LinuxEventWatcher(
            backend, backend.list_interfaces(), parse(list(argv)), emit=lines.append
        )
        lines.extend(watcher.start())
        return watcher, lines

    def msg(self, cmd, *attrs):
        raw = event(cmd, nl.attr_u32(nl.ATTR_IFINDEX, 3) + b"".join(attrs))
        return nl.to_genl(next(nl.iter_messages(raw)))

    def test_watching(self, kernel, backend):
        _w, lines = self.watcher(kernel, backend)
        assert lines[0] == (
            "(02:00:00:00:00:13), bssid: (02:00:00:00:00:21), freq: (5180), "
            "ssid: (ExampleNet), rssi: (-48), event: (watching), "
            "channel: (36@80 5 GHz), tx_rate: (864.5 Mbps)"
        )

    def test_disconnect_with_reason(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        (line,) = watcher.handle(
            self.msg(
                nl.CMD_DISCONNECT,
                nl.attr_u16(nl.ATTR_REASON_CODE, 3),
                nl.attr_flag(nl.ATTR_DISCONNECTED_BY_AP),
            )
        )
        assert "bssid: (02:00:00:00:00:21)" in line
        assert "event: (disconnected)" in line
        assert "reason: (3 " in line
        assert "locally_generated: (no)" in line
        assert line.record["reason_code"] == 3
        assert line.record["locally_generated"] is False

    def test_roam(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5975, last=0x13)
        ]
        kernel.stations = [station_attrs(0x22, -60, 2402)]
        (line,) = watcher.handle(
            self.msg(nl.CMD_ROAM, nl.pack_attr(nl.ATTR_MAC, mac(0x22)))
        )
        assert "bssid: (02:00:00:00:00:22)" in line
        assert "event: (roamed)" in line
        assert "old_bssid: (02:00:00:00:00:21)" in line
        assert "old_freq: (5180)" in line
        assert "channel: (5@80 6 GHz)" in line
        assert line.record["old_bssid"] == "02:00:00:00:00:21"
        assert line.record["freq_mhz"] == 5975

    def test_connect_and_failure(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        (ok,) = watcher.handle(
            self.msg(nl.CMD_CONNECT, nl.attr_u16(nl.ATTR_STATUS_CODE, 0))
        )
        assert "event: (connected)" in ok
        (bad,) = watcher.handle(
            self.msg(
                nl.CMD_CONNECT,
                nl.pack_attr(nl.ATTR_MAC, mac(0x23)),
                nl.attr_u16(nl.ATTR_STATUS_CODE, 17),
                nl.attr_flag(nl.ATTR_TIMED_OUT),
            )
        )
        assert "bssid: (02:00:00:00:00:23)" in bad
        assert "event: (connect_failed)" in bad
        assert bad.record["status_code"] == 17
        assert bad.record["timed_out"] is True

    def test_channel_switch(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        (line,) = watcher.handle(
            self.msg(
                nl.CMD_CH_SWITCH_NOTIFY,
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5500),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 5),
            )
        )
        assert "channel: (100@160 5 GHz), old_channel: (36@80 5 GHz)" in line

    def test_scan_results_only_with_debug(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        assert watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS)) == []
        watcher, _ = self.watcher(kernel, backend, ("--watchevents", "--debug"))
        (line,) = watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS))
        assert "scan: (1 BSSIDs found)" in line

    def test_other_interfaces_ignored(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        raw = event(nl.CMD_DISCONNECT, nl.attr_u32(nl.ATTR_IFINDEX, 42))
        assert watcher.handle(nl.to_genl(next(nl.iter_messages(raw)))) == []

    def test_json_record(self):
        formatter = LinkFormatter("02:00:00:00:00:13")
        formatter.last = LinkInfo(
            connected=True,
            bssid="02:00:00:00:00:21",
            ssid=b"ExampleNet",
            frequency_mhz=2412,
            rssi=-50,
        )
        line = formatter.disconnected(8, False)
        assert line.record["event"] == "disconnected"
        assert line.record["bssid"] == "02:00:00:00:00:21"
        assert line.record["reason_code"] == 8
        assert "freq_mhz" not in line.record

    def test_run_joins_groups(self, kernel, backend, monkeypatch):
        watcher, lines = self.watcher(kernel, backend)
        lines.clear()
        calls = []

        def stop(self, timeout=None):
            calls.append(self)
            raise KeyboardInterrupt

        monkeypatch.setattr(nl.GenericNetlink, "events", stop)
        with pytest.raises(KeyboardInterrupt):
            watcher.run()
        assert {8, 6} <= calls[0].sock.groups
        assert "event: (watching)" in lines[0]

    def test_watch_events_needs_interfaces(self, kernel, backend):
        kernel.interfaces = []
        with pytest.raises(BackendError, match="no Wi-Fi interfaces"):
            backend.watch_events(parse(["--watchevents"]))


def test_native_lookup_by_name(kernel, backend):
    iface = InterfaceInfo("wlan1", "", "", "", "", native=None)
    assert isinstance(backend._native(iface), LinuxInterface)
    with pytest.raises(BackendError):
        backend._native(InterfaceInfo("wlan9", "", "", "", "", native=None))


class TestUnknownSignal:
    """Drivers that send only SIGNAL_UNSPEC: no fake dBm, not threshold-filtered"""

    def test_record(self):
        attrs = nl.parse_attrs(bss_attrs(0x31, 5180, mbm=None, channel=36))
        record = bss_to_record(attrs)
        assert record.rssi_dbm is None
        assert record.link_quality == 60

    def test_shown_and_sorted(self, tmp_path):
        from lswifi import app, appsetup
        from lswifi.elements import WirelessNetworkBss

        records = [
            bss_to_record(nl.parse_attrs(bss_attrs(0x31, 5180, mbm=None, channel=36))),
            bss_to_record(nl.parse_attrs(bss_attrs(0x32, 5180, mbm=-4000, channel=36))),
        ]

        class Session:
            data = [WirelessNetworkBss(r) for r in records]
            mac = "02:00:00:00:00:13"
            last_scan_time_iso = "2026-01-01T00:00:00"

        args = appsetup.setup_parser().parse_args(
            ["-t", "-60", "--json", str(tmp_path / "out.json")]
        )
        out, *_rest, json_out, _new = app.lswifi().parse_bss_list(
            Session(), False, "", args.json, args
        )
        assert {row["bssid"] for row in json_out} == {
            "02:00:00:00:00:31",
            "02:00:00:00:00:32",
        }
        assert len(out) == 2
