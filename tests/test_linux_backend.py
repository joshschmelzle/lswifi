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
from lswifi.watchjson import dumps

FAMILY = 0x1C
CMD_NEW_WIPHY = 3
IFTYPE_P2P_DEVICE = 10
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
    ifindex,
    name,
    iftype=nl.IFTYPE_STATION,
    ssid=b"",
    freq=None,
    last=0x10,
    width=3,
    center1=None,
    center2=None,
    tx_mbm=2000,
    links=None,
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
            nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, width),
        ]
        if tx_mbm is not None:
            attrs.append(nl.attr_u32(nl.ATTR_WIPHY_TX_POWER_LEVEL, tx_mbm))
        if center1 is not None:
            attrs.append(nl.attr_u32(nl.ATTR_CENTER_FREQ1, center1))
        if center2 is not None:
            attrs.append(nl.attr_u32(nl.ATTR_CENTER_FREQ2, center2))
    if links:
        attrs.append(nl.pack_nested(nl.ATTR_MLO_LINKS, links))
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
        self.link_stations: list[bytes] | None = None
        self.reject_link_stats = False
        self.surveys: list[bytes] = []
        self.band_payloads = None
        self.wiphy_messages = None
        self.survey_error = 0
        self.wiphy_error = 0
        self.trigger_error = 0
        self.scan_event = nl.CMD_NEW_SCAN_RESULTS
        self.alpha2 = "US"
        self.bands = [0, 1]
        self.reject_scan_flags = False
        self.stale_results = False
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
            if self.wiphy_error:
                return [nl.build_error(seq, -self.wiphy_error)]
            if self.stale_results:
                self.broadcast(
                    "scan",
                    event(nl.CMD_NEW_SCAN_RESULTS, nl.attr_u32(nl.ATTR_IFINDEX, 5)),
                )
            if self.wiphy_messages is not None:
                items = self.wiphy_messages
            else:
                bands = (
                    self.band_payloads
                    if self.band_payloads is not None
                    else [nl.pack_attr(band, b"") for band in self.bands]
                )
                items = [
                    nl.attr_u32(nl.ATTR_WIPHY, 0)
                    + nl.pack_nested(nl.ATTR_WIPHY_BANDS, bands)
                ]
            return multi(CMD_NEW_WIPHY, items)
        if msg.cmd == nl.CMD_GET_STATION:
            flagged = nl.ATTR_STA_DUMP_LINK_STATS in msg.attrs
            if flagged and self.reject_link_stats:
                return [nl.build_error(seq, -errno.EINVAL)]
            items = (
                self.link_stations
                if flagged and self.link_stations is not None
                else self.stations
            )
            return multi(nl.CMD_NEW_STATION, items)
        if msg.cmd == nl.CMD_GET_SURVEY:
            if self.survey_error:
                return [nl.build_error(seq, -self.survey_error)]
            return multi(nl.CMD_NEW_SURVEY_RESULTS, self.surveys)
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
            if self.reject_scan_flags and nl.ATTR_SCAN_FLAGS in msg.attrs:
                return [nl.build_error(seq, -errno.EINVAL)]
            ifindex = nl.get_uint(msg.attrs, nl.ATTR_IFINDEX)
            self.broadcast(
                "scan",
                event(nl.CMD_TRIGGER_SCAN, nl.attr_u32(nl.ATTR_IFINDEX, ifindex)),
            )
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
    def __init__(self, up=True, driver="mt7921u"):
        super().__init__("/nonexistent")
        self.up = up
        self.driver_name = driver

    def is_up(self, name):
        return self.up

    def driver(self, name):
        return self.driver_name

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
            nl.attr_u32(nl.ATTR_IFTYPE, IFTYPE_P2P_DEVICE),
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
        assert ssids == {1: b""}
        assert PERMISSION_HELP not in caplog.text

    def test_unprivileged_falls_back_to_cache(self, kernel, backend, caplog):
        kernel.trigger_error = errno.EPERM
        records = backend.scan(self.iface(backend))
        assert len(records) == 1
        assert caplog.text.count("CAP_NET_ADMIN") == 1
        backend.scan(self.iface(backend))
        assert caplog.text.count("CAP_NET_ADMIN") == 1

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

    def test_rejected_scan_flags_retry_without(self, kernel, backend, caplog):
        kernel.bands = [0, 1, nl.BAND_6GHZ]
        kernel.reject_scan_flags = True
        assert len(backend.scan(self.iface(backend))) == 1
        triggers = [m for m in kernel.sent if m.cmd == nl.CMD_TRIGGER_SCAN]
        assert [nl.ATTR_SCAN_FLAGS in m.attrs for m in triggers] == [True, False]
        assert "did not finish" not in caplog.text
        backend.scan(self.iface(backend))
        triggers = [m for m in kernel.sent if m.cmd == nl.CMD_TRIGGER_SCAN]
        assert nl.ATTR_SCAN_FLAGS not in triggers[-1].attrs

    def test_stale_results_do_not_end_wait(self, kernel, backend, caplog):
        kernel.stale_results = True
        kernel.scan_event = 0
        backend.scan(self.iface(backend))
        assert "did not finish" in caplog.text

    def test_results_before_start_ignored(self, kernel, backend, caplog):
        kernel.stale_results = True
        backend.scan(self.iface(backend))
        assert "did not finish" not in caplog.text

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

    def test_whole_tx_rate_and_missing_bus(self, kernel, backend, monkeypatch):
        iface = self.connected(kernel, backend)
        kernel.stations = [station_attrs(0x21, -48, 5760)]
        monkeypatch.setattr(backend.sysfs, "bus_info", lambda name: (None, None))
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Transmit (Tx) Rate: 576 Mbps" in out
        assert "Bus:" not in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["bus"] is None
        assert info["tx_rate_mbps"] == 576.0

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
        out = backend.interface_info(parse(["--get-interfaces"]), iface)
        assert "Channel:" not in out
        assert "Frequency:" not in out
        assert "SSID" not in out

    def test_json(self, kernel, backend):
        out = backend.interface_info(
            parse(["--get-interfaces", "--json"]), self.connected(kernel, backend)
        )
        info = json.loads(out)
        assert info["bssid"] == "02:00:00:00:00:21"
        assert info["channel"] == 36
        assert info["state"] == "connected"
        assert info["links"] is None
        assert info["ap_mld"] is None
        assert info["frequency_mhz"] == 5180
        assert info["band"] == "5 GHz"
        assert info["width_mhz"] == 80
        assert set(info) == {
            "interface",
            "mac",
            "description",
            "state",
            "ssid",
            "bssid",
            "ap_mld",
            "channel",
            "frequency_mhz",
            "band",
            "width_mhz",
            "center_freq1_mhz",
            "center_freq2_mhz",
            "interface_mode",
            "rssi",
            "signal_chains",
            "signal_avg",
            "signal_avg_chains",
            "beacon_signal_avg",
            "ack_signal",
            "ack_signal_avg",
            "tx_rate_mbps",
            "tx_rate",
            "rx_rate_mbps",
            "rx_rate",
            "tx_retries",
            "tx_failed",
            "rx_packets",
            "tx_packets",
            "rx_bytes",
            "tx_bytes",
            "tx_duration_us",
            "rx_duration_us",
            "connected_time_s",
            "inactive_time_ms",
            "beacon_loss",
            "expected_throughput_mbps",
            "channel_busy_percent",
            "tx_power_dbm",
            "supported_channels",
            "phy",
            "gateway_ip",
            "gateway_mac",
            "links",
            "country_code",
            "bus",
        }

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
        assert "AP uptime isn't available on Linux" in out


def s8(kind, value):
    return nl.pack_attr(kind, struct.pack("=b", value))


def legacy_bitrate(kind, units):
    return nl.pack_nested(kind, [nl.attr_u16(nl.RATE_INFO_BITRATE, units)])


def associated_bss(bssid, freq, link_id=None, mld=None):
    attrs = [
        nl.pack_attr(nl.BSS_BSSID, bssid),
        nl.attr_u32(nl.BSS_FREQUENCY, freq),
        nl.attr_u32(nl.BSS_STATUS, nl.BSS_STATUS_ASSOCIATED),
    ]
    if link_id is not None:
        attrs.append(nl.attr_u8(nl.BSS_MLO_LINK_ID, link_id))
    if mld is not None:
        attrs.append(nl.pack_attr(nl.BSS_MLD_ADDR, mld))
    return b"".join(attrs)


def station_message(bssid, sta=None, links=None):
    attrs = [nl.pack_attr(nl.ATTR_MAC, bssid)]
    if sta is not None:
        attrs.append(nl.pack_nested(nl.ATTR_STA_INFO, sta))
    if links:
        attrs.append(nl.pack_nested(nl.ATTR_MLO_LINKS, links))
    return b"".join(attrs)


def mlo_link(
    link_id, bssid, freq=None, sta=None, *, width=None, center1=None, tx_mbm=None
):
    attrs = [
        nl.attr_u8(nl.ATTR_MLO_LINK_ID, link_id),
        nl.pack_attr(nl.ATTR_MAC, bssid),
    ]
    if freq is not None:
        attrs.append(nl.attr_u32(nl.ATTR_WIPHY_FREQ, freq))
    if width is not None:
        attrs.append(nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, width))
    if center1 is not None:
        attrs.append(nl.attr_u32(nl.ATTR_CENTER_FREQ1, center1))
    if tx_mbm is not None:
        attrs.append(nl.attr_u32(nl.ATTR_WIPHY_TX_POWER_LEVEL, tx_mbm))
    if sta is not None:
        attrs.append(nl.pack_nested(nl.ATTR_STA_INFO, sta))
    return nl.pack_nested(link_id + 1, attrs)


def chain_signals(kind, values):
    return nl.pack_nested(
        kind, [s8(index, value) for index, value in enumerate(values)]
    )


MT_STA = [
    nl.attr_u32(nl.STA_INFO_INACTIVE_TIME, 512),
    nl.attr_u32(nl.STA_INFO_RX_BYTES, 3780),
    nl.attr_u32(nl.STA_INFO_TX_BYTES, 817),
    s8(nl.STA_INFO_SIGNAL, -44),
    legacy_bitrate(nl.STA_INFO_TX_BITRATE, 240),
    nl.attr_u32(nl.STA_INFO_RX_PACKETS, 20),
    nl.attr_u32(nl.STA_INFO_TX_PACKETS, 7),
    nl.attr_u32(nl.STA_INFO_TX_RETRIES, 0),
    nl.attr_u32(nl.STA_INFO_TX_FAILED, 0),
    s8(nl.STA_INFO_SIGNAL_AVG, -43),
    legacy_bitrate(nl.STA_INFO_RX_BITRATE, 240),
    nl.attr_u32(nl.STA_INFO_CONNECTED_TIME, 0),
    nl.attr_u32(nl.STA_INFO_BEACON_LOSS, 0),
    chain_signals(nl.STA_INFO_CHAIN_SIGNAL, (-48, -45)),
    chain_signals(nl.STA_INFO_CHAIN_SIGNAL_AVG, (-48, -44)),
    nl.attr_u32(nl.STA_INFO_EXPECTED_THROUGHPUT, 19500),
    nl.attr_u64(nl.STA_INFO_RX_DURATION, 1240),
    s8(nl.STA_INFO_ACK_SIGNAL, -44),
    s8(nl.STA_INFO_ACK_SIGNAL_AVG, -43),
    nl.attr_u64(nl.STA_INFO_TX_DURATION, 6022),
]

EHT_TX = nl.pack_nested(
    nl.STA_INFO_TX_BITRATE,
    [
        nl.attr_u32(nl.RATE_INFO_BITRATE32, 2882),
        nl.attr_flag(nl.RATE_INFO_80_MHZ_WIDTH),
        nl.attr_u8(nl.RATE_INFO_EHT_MCS, 3),
        nl.attr_u8(nl.RATE_INFO_EHT_NSS, 2),
        nl.attr_u8(nl.RATE_INFO_EHT_GI, 0),
    ],
)

BE_STA = [
    nl.attr_u32(nl.STA_INFO_INACTIVE_TIME, 15808),
    nl.attr_u32(nl.STA_INFO_RX_BYTES, 52323),
    nl.attr_u32(nl.STA_INFO_TX_BYTES, 1795),
    s8(nl.STA_INFO_SIGNAL, -41),
    EHT_TX,
    nl.attr_u32(nl.STA_INFO_RX_PACKETS, 214),
    nl.attr_u32(nl.STA_INFO_TX_PACKETS, 14),
    nl.attr_u32(nl.STA_INFO_TX_RETRIES, 0),
    nl.attr_u32(nl.STA_INFO_TX_FAILED, 0),
    s8(nl.STA_INFO_SIGNAL_AVG, -41),
    legacy_bitrate(nl.STA_INFO_RX_BITRATE, 240),
    nl.attr_u32(nl.STA_INFO_CONNECTED_TIME, 19),
    nl.attr_u32(nl.STA_INFO_BEACON_LOSS, 0),
    s8(nl.STA_INFO_BEACON_SIGNAL_AVG, -41),
    nl.attr_u64(nl.STA_INFO_RX_DURATION, 0),
    nl.attr_u64(nl.STA_INFO_TX_DURATION, 0),
]

MLD = bytes.fromhex("6851347c3205")


def line(out, label):
    return next(
        item.strip() for item in out.splitlines() if item.strip().startswith(label)
    )


def freq_attr(index, mhz, radar=False, no_ir=False, disabled=False):
    attrs = [nl.attr_u32(nl.FREQ_ATTR_FREQ, mhz)]
    if disabled:
        attrs.append(nl.attr_flag(nl.FREQ_ATTR_DISABLED))
    if radar:
        attrs.append(nl.attr_flag(nl.FREQ_ATTR_RADAR))
    if no_ir:
        attrs.append(nl.attr_flag(nl.FREQ_ATTR_NO_IR))
    return nl.pack_nested(index, attrs)


def band_payload(band_id, freqs, ht=False, vht=False, he=False, eht=False):
    attrs = []
    if freqs:
        attrs.append(nl.pack_nested(nl.BAND_ATTR_FREQS, freqs))
    if ht:
        attrs.append(nl.attr_u16(nl.BAND_ATTR_HT_CAPA, 1))
    if vht:
        attrs.append(nl.attr_u32(nl.BAND_ATTR_VHT_CAPA, 1))
    caps = []
    if he:
        caps.append(nl.pack_attr(nl.BAND_IFTYPE_HE_CAP_PHY, b"\x00"))
    if eht:
        caps.append(nl.pack_attr(nl.BAND_IFTYPE_EHT_CAP_MAC, b"\x00"))
    if caps:
        attrs.append(
            nl.pack_nested(nl.BAND_ATTR_IFTYPE_DATA, [nl.pack_nested(1, caps)])
        )
    return nl.pack_nested(band_id, attrs)


class TestInterfaceDetails:
    def text(self, kernel, backend):
        iface = backend.list_interfaces()[0]
        return backend.interface_info(parse(["--get-interfaces"]), iface), iface

    def test_mt7921u_legacy_rates_and_chains(self, kernel, backend, tmp_path, caplog):
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan1",
                ssid=b"sae-6",
                freq=6135,
                center1=6145,
                tx_mbm=1200,
                last=0x58,
            )
        ]
        kernel.stations = [station_message(mac(0x21), MT_STA)]
        backend.proc_net = str(tmp_path)
        out, iface = self.text(kernel, backend)
        assert "Interface: wlan1 is connected" in out
        assert line(out, "RSSI:") == "RSSI: -44 dBm (chains -48, -45)"
        assert line(out, "Signal Avg:") == "Signal Avg: -43 dBm (chains -48, -44)"
        assert line(out, "Transmit (Tx) Rate:") == "Transmit (Tx) Rate: 24 Mbps"
        assert line(out, "Receive (Rx) Rate:") == "Receive (Rx) Rate: 24 Mbps"
        assert "MCS" not in out
        assert line(out, "Ack Signal:") == "Ack Signal: -44 dBm"
        assert line(out, "Ack Signal Avg:") == "Ack Signal Avg: -43 dBm"
        assert line(out, "Tx Duration:") == "Tx Duration: 6022 us"
        assert line(out, "Rx Duration:") == "Rx Duration: 1240 us"
        assert line(out, "Expected Throughput:") == "Expected Throughput: 19.5 Mbps"
        assert line(out, "Connected Time:") == "Connected Time: 0 s"
        assert line(out, "Tx Retries:") == "Tx Retries: 0"
        assert line(out, "Channel:") == "Channel: 37"
        assert line(out, "Center Frequency:") == "Center Frequency: 6145 MHz"
        assert line(out, "Transmit Power:") == "Transmit Power: 12 dBm"
        assert "Beacon Signal Avg" not in out
        assert "Channel Busy" not in out
        assert "Gateway" not in out
        assert "Link " not in out
        assert "WARNING" not in caplog.text
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["tx_rate_mbps"] == 24.0
        assert info["rx_rate"]["phy"] is None
        assert info["signal_chains"] == [-48, -45]
        assert info["links"] is None
        assert info["channel_busy_percent"] is None
        assert info["gateway_ip"] is None

    def test_brcmfmac_disconnected_channel_and_world_domain(self, kernel, backend):
        backend.sysfs.driver_name = "brcmfmac"
        kernel.alpha2 = "00"
        kernel.interfaces = [
            iface_attrs(3, "wlan0", freq=5180, width=1, center1=5180, tx_mbm=None)
        ]
        out, iface = self.text(kernel, backend)
        assert "is disconnected" in out
        assert "Description: brcmfmac (phy0)" in out
        assert line(out, "Channel:") == "Channel: 36"
        assert line(out, "Frequency:") == "Frequency: 5180 MHz"
        assert line(out, "Width:") == "Width: 20 MHz"
        assert line(out, "Center Frequency:") == "Center Frequency: 5180 MHz"
        assert line(out, "Mode:") == "Mode: managed"
        assert line(out, "Country Code:") == "Country Code: 00 (world)"
        assert "SSID" not in out
        assert "RSSI" not in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["country_code"] == "00"
        assert info["frequency_mhz"] == 5180
        assert info["channel"] == 36
        assert info["rssi"] is None
        assert info["tx_rate_mbps"] is None

    def _be200(self, kernel, stations):
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"sae-6",
                freq=6135,
                center1=6145,
                tx_mbm=2200,
                last=0x63,
            )
        ]
        kernel.stations = stations

    def test_be200_mlo_eht_and_legacy(self, kernel, backend, tmp_path, caplog):
        backend.sysfs.driver_name = "iwlwifi"
        backend.proc_net = str(tmp_path)
        link = mlo_link(0, MLD, 6135)
        self._be200(
            kernel,
            [
                station_message(MLD, BE_STA),
                station_message(MLD, links=[link]),
            ],
        )
        out, iface = self.text(kernel, backend)
        assert out.count("Transmit (Tx) Rate:") == 1
        assert line(out, "Transmit (Tx) Rate:") == (
            "Transmit (Tx) Rate: 288.2 Mbps, EHT, MCS 3, NSS 2, 80 MHz, GI 0.8"
        )
        assert line(out, "Receive (Rx) Rate:") == "Receive (Rx) Rate: 24 Mbps"
        assert line(out, "Link 0:") == (
            "Link 0: AP BSSID 68:51:34:7c:32:05, channel 37, 6135 MHz, 6 GHz"
        )
        assert line(out, "RSSI:") == "RSSI: -41 dBm"
        assert "(chains" not in out
        assert line(out, "Beacon Signal Avg:") == "Beacon Signal Avg: -41 dBm"
        assert "Tx Duration:" not in out
        assert "Rx Duration:" not in out
        assert line(out, "Connected Time:") == "Connected Time: 19 s"
        assert line(out, "Inactive Time:") == "Inactive Time: 15808 ms"
        assert line(out, "Beacon Loss:") == "Beacon Loss: 0"
        assert line(out, "Rx Packets:") == "Rx Packets: 214"
        assert line(out, "Tx Packets:") == "Tx Packets: 14"
        assert line(out, "Rx Bytes:") == "Rx Bytes: 52323"
        assert line(out, "Tx Bytes:") == "Tx Bytes: 1795"
        assert line(out, "Channel:") == "Channel: 37"
        assert line(out, "Width:") == "Width: 80 MHz"
        assert line(out, "Center Frequency:") == "Center Frequency: 6145 MHz"
        assert line(out, "Transmit Power:") == "Transmit Power: 22 dBm"
        assert "Channel Busy" not in out
        assert "Gateway" not in out
        assert "Ack Signal" not in out
        assert "WARNING" not in caplog.text
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["tx_rate_mbps"] == 288.2
        assert info["rx_rate_mbps"] == 24.0
        assert info["tx_rate"]["phy"] == "EHT"
        assert info["tx_rate"]["gi"] == "0.8"
        assert info["rx_rate"]["phy"] is None
        assert info["signal_chains"] is None
        assert info["beacon_signal_avg"] == -41
        assert info["tx_duration_us"] is None
        assert info["rx_duration_us"] is None
        assert info["links"] == [
            {
                "id": 0,
                "bssid": "68:51:34:7c:32:05",
                "frequency_mhz": 6135,
                "channel": 37,
                "band": "6 GHz",
                "active": None,
                "stats": None,
            }
        ]
        assert info["ap_mld"] == "68:51:34:7c:32:05"
        assert info["interface_mode"] == "managed"

    def test_mlo_stats_only_inside_one_link(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        self._be200(
            kernel, [station_message(MLD, links=[mlo_link(0, MLD, 6135, BE_STA)])]
        )
        out, _iface = self.text(kernel, backend)
        assert line(out, "Transmit (Tx) Rate:") == (
            "Transmit (Tx) Rate: 288.2 Mbps, EHT, MCS 3, NSS 2, 80 MHz, GI 0.8"
        )
        assert line(out, "Receive (Rx) Rate:") == "Receive (Rx) Rate: 24 Mbps"
        assert line(out, "Link 0:") == (
            "Link 0: AP BSSID 68:51:34:7c:32:05, channel 37, 6135 MHz, 6 GHz, "
            "signal -41 dBm, signal avg -41 dBm, rx 52323 B, tx 1795 B, "
            "rx 214 pkts, tx 14 pkts, rx 24 Mbps, tx 288.2 Mbps"
        )
        assert out.count("Transmit (Tx) Rate:") == 1

    def test_top_level_stats_win_over_per_link(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        decoy = [legacy_bitrate(nl.STA_INFO_RX_BITRATE, 60)]
        self._be200(
            kernel,
            [station_message(MLD, BE_STA, [mlo_link(0, MLD, 6135, decoy)])],
        )
        out, _iface = self.text(kernel, backend)
        assert line(out, "Receive (Rx) Rate:") == "Receive (Rx) Rate: 24 Mbps"
        assert "6 Mbps" not in line(out, "Receive (Rx) Rate:")
        assert "rx 6 Mbps" in line(out, "Link 0:")

    def test_two_links_without_aggregate_are_not_hoisted(
        self, kernel, backend, tmp_path
    ):
        backend.proc_net = str(tmp_path)
        other = bytes.fromhex("6851347c3206")
        self._be200(
            kernel,
            [
                station_message(
                    MLD,
                    links=[
                        mlo_link(0, MLD, 6135, BE_STA),
                        mlo_link(1, other, 5210, BE_STA),
                    ],
                )
            ],
        )
        out, _iface = self.text(kernel, backend)
        assert "Transmit (Tx) Rate:" not in out
        per_link = (
            "signal -41 dBm, signal avg -41 dBm, rx 52323 B, tx 1795 B, "
            "rx 214 pkts, tx 14 pkts, rx 24 Mbps, tx 288.2 Mbps"
        )
        assert line(out, "Link 0:") == (
            "Link 0: AP BSSID 68:51:34:7c:32:05, channel 37, 6135 MHz, 6 GHz, "
            + per_link
        )
        assert line(out, "Link 1:") == (
            "Link 1: AP BSSID 68:51:34:7c:32:06, channel 42, 5210 MHz, 5 GHz, "
            + per_link
        )

    def test_interface_mlo_link_is_the_channel(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        addr = bytes.fromhex("a6b1f5a21e29")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"sae-6",
                freq=None,
                links=[mlo_link(0, addr, 6135, width=3, center1=6145, tx_mbm=2200)],
                last=0x63,
            )
        ]
        kernel.stations = [station_message(MLD, BE_STA)]
        out, iface = self.text(kernel, backend)
        assert line(out, "Link 0 (active):") == (
            "Link 0 (active): STA a6:b1:f5:a2:1e:29, channel 37, 6135 MHz, 6 GHz, "
            "80 MHz, center 6145 MHz, 22 dBm"
        )
        assert line(out, "Channel:") == "Channel: 37"
        assert line(out, "Frequency:") == "Frequency: 6135 MHz"
        assert line(out, "Band:") == "Band: 6 GHz"
        assert line(out, "Width:") == "Width: 80 MHz"
        assert line(out, "Center Frequency:") == "Center Frequency: 6145 MHz"
        assert line(out, "Transmit Power:") == "Transmit Power: 22 dBm"
        assert line(out, "RSSI:") == "RSSI: -41 dBm"
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["channel"] == 37
        assert info["width_mhz"] == 80
        assert info["center_freq1_mhz"] == 6145
        assert info["tx_power_dbm"] == 22.0
        assert info["links"][0]["addr"] == "a6:b1:f5:a2:1e:29"

    def test_two_link_mlo_emlsr(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        active = bytes.fromhex("a6b1f5a21e29")
        quiet = bytes.fromhex("7ae3a942cd3a")
        link2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"sae-6",
                freq=None,
                links=[
                    mlo_link(0, active, 6135, width=3, center1=6145, tx_mbm=2200),
                    mlo_link(2, quiet),
                ],
                last=0x63,
            )
        ]
        kernel.stations = [
            station_message(
                MLD,
                [
                    s8(nl.STA_INFO_SIGNAL, 0),
                    EHT_TX,
                    legacy_bitrate(nl.STA_INFO_RX_BITRATE, 240),
                ],
                [mlo_link(0, MLD, 6135), mlo_link(2, link2, 2462)],
            )
        ]
        out, iface = self.text(kernel, backend)
        assert line(out, "AP MLD:") == "AP MLD: 68:51:34:7c:32:05"
        assert "\n    BSSID:" not in out
        assert line(out, "Link 0 (active):") == (
            "Link 0 (active): AP BSSID 68:51:34:7c:32:05, STA a6:b1:f5:a2:1e:29, "
            "channel 37, 6135 MHz, 6 GHz, 80 MHz, center 6145 MHz, 22 dBm"
        )
        assert line(out, "Link 2:") == (
            "Link 2: AP BSSID 68:51:34:7c:31:f5, STA 7a:e3:a9:42:cd:3a, channel 11, "
            "2462 MHz, 2.4 GHz"
        )
        assert line(out, "Channel:") == "Channel: 37"
        assert line(out, "Frequency:") == "Frequency: 6135 MHz"
        assert line(out, "Band:") == "Band: 6 GHz"
        assert line(out, "Width:") == "Width: 80 MHz"
        assert line(out, "Center Frequency:") == "Center Frequency: 6145 MHz"
        assert line(out, "Transmit Power:") == "Transmit Power: 22 dBm"
        assert "RSSI" not in out
        assert line(out, "Transmit (Tx) Rate:") == (
            "Transmit (Tx) Rate: 288.2 Mbps, EHT, MCS 3, NSS 2, 80 MHz, GI 0.8"
        )
        assert line(out, "Receive (Rx) Rate:") == "Receive (Rx) Rate: 24 Mbps"
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["rssi"] is None
        assert info["channel"] == 37
        assert info["frequency_mhz"] == 6135
        assert info["band"] == "6 GHz"
        assert info["width_mhz"] == 80
        assert info["center_freq1_mhz"] == 6145
        assert info["tx_power_dbm"] == 22.0
        assert info["tx_rate_mbps"] == 288.2
        assert info["rx_rate_mbps"] == 24.0
        assert info["links"][0]["id"] == 0
        assert info["links"][0]["bssid"] == "68:51:34:7c:32:05"
        assert info["links"][0]["addr"] == "a6:b1:f5:a2:1e:29"
        assert info["links"][0]["width_mhz"] == 80
        assert info["links"][0]["center_freq1_mhz"] == 6145
        assert info["links"][0]["tx_power_dbm"] == 22.0
        assert info["links"][1]["id"] == 2
        assert info["links"][1]["frequency_mhz"] == 2462
        assert info["links"][1]["channel"] == 11
        assert info["links"][1]["band"] == "2.4 GHz"
        assert "width_mhz" not in info["links"][1]
        assert "tx_power_dbm" not in info["links"][1]
        assert info["links"][0]["active"] is True
        assert info["links"][1]["active"] is False
        assert info["links"][0]["stats"] is None
        assert info["links"][1]["stats"] is None
        assert info["ap_mld"] == info["bssid"] == "68:51:34:7c:32:05"

    def test_placeholder_mld_signal_dropped_with_per_link_signal(
        self, kernel, backend, tmp_path
    ):
        backend.proc_net = str(tmp_path)
        active = bytes.fromhex("a6b1f5a21e29")
        quiet = bytes.fromhex("7ae3a942cd3a")
        link2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"sae-6",
                freq=None,
                links=[
                    mlo_link(0, active, 6135, width=3, center1=6145, tx_mbm=2200),
                    mlo_link(2, quiet),
                ],
                last=0x63,
            )
        ]
        kernel.stations = [
            station_message(
                MLD,
                [
                    s8(nl.STA_INFO_SIGNAL, 0),
                    EHT_TX,
                    legacy_bitrate(nl.STA_INFO_RX_BITRATE, 240),
                ],
                [
                    mlo_link(0, MLD, 6135, [s8(nl.STA_INFO_SIGNAL, -40)]),
                    mlo_link(2, link2, 2462, [s8(nl.STA_INFO_SIGNAL, -62)]),
                ],
            )
        ]
        out, iface = self.text(kernel, backend)
        assert "RSSI" not in out
        assert line(out, "Link 0 (active):") == (
            "Link 0 (active): AP BSSID 68:51:34:7c:32:05, STA a6:b1:f5:a2:1e:29, "
            "channel 37, 6135 MHz, 6 GHz, 80 MHz, center 6145 MHz, 22 dBm, "
            "signal -40 dBm"
        )
        assert line(out, "Link 2:") == (
            "Link 2: AP BSSID 68:51:34:7c:31:f5, STA 7a:e3:a9:42:cd:3a, channel 11, "
            "2462 MHz, 2.4 GHz, signal -62 dBm"
        )
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["rssi"] is None
        lines: list = []
        watcher = LinuxEventWatcher(
            backend,
            backend.list_interfaces(),
            parse(["--watchevents"]),
            emit=lines.append,
        )
        (watching,) = watcher.start()
        assert "rssi:" not in watching
        assert watching.record["rssi"] is None
        assert [item["id"] for item in watching.record["links"]] == [0, 2]

    def test_bss_dump_supplies_ap_link_bssid_and_frequency(
        self, kernel, backend, tmp_path
    ):
        backend.proc_net = str(tmp_path)
        active = bytes.fromhex("a6b1f5a21e29")
        quiet = bytes.fromhex("7ae3a942cd3a")
        link2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"sae-6",
                freq=None,
                links=[
                    mlo_link(0, active, 6135, width=3, center1=6145, tx_mbm=2200),
                    mlo_link(2, quiet),
                ],
                last=0x63,
            )
        ]
        kernel.stations = [
            station_message(
                MLD,
                [s8(nl.STA_INFO_SIGNAL, -41), EHT_TX],
                [mlo_link(0, active), mlo_link(2, quiet)],
            )
        ]
        kernel.bss = [
            associated_bss(MLD, 6135, 0, MLD),
            associated_bss(link2, 2462, 2, MLD),
            bss_attrs(0x44, 2412, channel=1),
            associated_bss(mac(0x99), 5220),
        ]
        out, iface = self.text(kernel, backend)
        assert line(out, "AP MLD:") == "AP MLD: 68:51:34:7c:32:05"
        assert line(out, "Link 0 (active):") == (
            "Link 0 (active): AP BSSID 68:51:34:7c:32:05, STA a6:b1:f5:a2:1e:29, "
            "channel 37, 6135 MHz, 6 GHz, 80 MHz, center 6145 MHz, 22 dBm"
        )
        assert line(out, "Link 2:") == (
            "Link 2: AP BSSID 68:51:34:7c:31:f5, STA 7a:e3:a9:42:cd:3a, channel 11, "
            "2462 MHz, 2.4 GHz"
        )
        assert "02:00:00:00:00:44" not in out
        assert "02:00:00:00:00:99" not in out
        assert line(out, "Channel:") == "Channel: 37"
        assert line(out, "Frequency:") == "Frequency: 6135 MHz"
        assert line(out, "Band:") == "Band: 6 GHz"
        assert line(out, "Width:") == "Width: 80 MHz"
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["channel"] == 37
        assert info["frequency_mhz"] == 6135
        assert info["band"] == "6 GHz"
        assert info["width_mhz"] == 80
        assert info["center_freq1_mhz"] == 6145
        assert info["tx_power_dbm"] == 22.0
        assert info["bssid"] == "68:51:34:7c:32:05"
        assert info["links"][0]["bssid"] == "68:51:34:7c:32:05"
        assert info["links"][0]["addr"] == "a6:b1:f5:a2:1e:29"
        assert info["links"][1]["bssid"] == "68:51:34:7c:31:f5"
        assert info["links"][1]["addr"] == "7a:e3:a9:42:cd:3a"
        assert info["links"][1]["frequency_mhz"] == 2462
        assert info["links"][1]["channel"] == 11
        assert info["links"][1]["band"] == "2.4 GHz"
        assert len(info["links"]) == 2

    def _three_link_active_on_one(self, kernel):
        sta0 = bytes.fromhex("a6b1f5a21e29")
        sta1 = bytes.fromhex("a6b1f5a21e2a")
        sta2 = bytes.fromhex("a6b1f5a21e2b")
        ap1 = bytes.fromhex("6851347c3206")
        ap2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"mlo-net",
                freq=None,
                links=[
                    mlo_link(0, sta0),
                    mlo_link(1, sta1, 5280, width=1, center1=5280, tx_mbm=2200),
                    mlo_link(2, sta2, tx_mbm=1800),
                ],
                last=0x63,
            )
        ]
        kernel.bss = [
            associated_bss(MLD, 5975, 0, MLD),
            associated_bss(ap1, 5280, 1, MLD),
            associated_bss(ap2, 2462, 2, MLD),
        ]
        return ap1, ap2

    def test_active_link_channel_is_not_link_zero(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        ap1, _ap2 = self._three_link_active_on_one(kernel)
        kernel.stations = [
            station_message(
                MLD,
                [s8(nl.STA_INFO_SIGNAL, -45), EHT_TX],
                [
                    mlo_link(0, MLD),
                    mlo_link(1, ap1),
                    mlo_link(2, bytes.fromhex("6851347c31f5")),
                ],
            )
        ]
        out, iface = self.text(kernel, backend)
        assert line(out, "Channel:") == "Channel: 56"
        assert line(out, "Frequency:") == "Frequency: 5280 MHz"
        assert line(out, "Band:") == "Band: 5 GHz"
        assert line(out, "Width:") == "Width: 20 MHz"
        assert line(out, "Center Frequency:") == "Center Frequency: 5280 MHz"
        assert "Link 1 (active):" in out
        assert "Link 0 (active)" not in out
        assert "Link 2 (active)" not in out
        assert "5975 MHz" in line(out, "Link 0:")
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["channel"] == 56
        assert info["frequency_mhz"] == 5280
        assert info["band"] == "5 GHz"
        assert info["width_mhz"] == 20
        assert info["center_freq1_mhz"] == 5280
        assert info["bssid"] == "68:51:34:7c:32:05"
        assert info["ap_mld"] == "68:51:34:7c:32:05"
        assert [item["active"] for item in info["links"]] == [False, True, False]
        assert info["links"][0]["frequency_mhz"] == 5975
        assert info["links"][1]["frequency_mhz"] == 5280
        assert info["links"][1]["channel"] == 56
        assert info["links"][2]["frequency_mhz"] == 2462
        assert "width_mhz" not in info["links"][0]
        assert info["links"][1]["width_mhz"] == 20
        assert "width_mhz" not in info["links"][2]
        assert info["links"][2]["tx_power_dbm"] == 18.0

    def test_association_link_when_no_link_is_active(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        sta0 = bytes.fromhex("a6b1f5a21e29")
        sta1 = bytes.fromhex("a6b1f5a21e2a")
        sta2 = bytes.fromhex("a6b1f5a21e2b")
        ap1 = bytes.fromhex("6851347c3206")
        ap2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"mlo-net",
                freq=None,
                links=[mlo_link(0, sta0), mlo_link(1, sta1), mlo_link(2, sta2)],
                last=0x63,
            )
        ]
        kernel.bss = [
            associated_bss(MLD, 5975, 0, MLD),
            associated_bss(ap1, 5280, 1, MLD),
            associated_bss(ap2, 2462, 2, MLD),
        ]
        kernel.stations = [
            station_message(MLD, [s8(nl.STA_INFO_SIGNAL, -40)])
            + nl.attr_u8(nl.ATTR_MLO_LINK_ID, 1)
        ]
        _out, iface = self.text(kernel, backend)
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["frequency_mhz"] == 5280
        assert info["channel"] == 56
        assert info["band"] == "5 GHz"
        assert info["width_mhz"] is None
        assert [item["active"] for item in info["links"]] == [False, False, False]

    def test_several_active_links_prefer_the_association_link(
        self, kernel, backend, tmp_path
    ):
        backend.proc_net = str(tmp_path)
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"mlo-net",
                freq=None,
                links=[
                    mlo_link(
                        0,
                        bytes.fromhex("a6b1f5a21e29"),
                        5975,
                        width=5,
                        center1=6025,
                        tx_mbm=2200,
                    ),
                    mlo_link(
                        1,
                        bytes.fromhex("a6b1f5a21e2a"),
                        5280,
                        width=1,
                        center1=5280,
                        tx_mbm=2000,
                    ),
                ],
                last=0x63,
            )
        ]
        kernel.stations = [
            station_message(MLD, [s8(nl.STA_INFO_SIGNAL, -40)])
            + nl.attr_u8(nl.ATTR_MLO_LINK_ID, 1)
        ]
        iface = backend.list_interfaces()[0]
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert [item["active"] for item in info["links"]] == [True, True]
        assert info["frequency_mhz"] == 5280
        assert info["channel"] == 56
        assert info["width_mhz"] == 20
        assert info["center_freq1_mhz"] == 5280
        assert info["tx_power_dbm"] == 20.0
        assert info["ap_mld"] == "68:51:34:7c:32:05"

    def test_per_link_station_stats_follow_the_dump(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        ap1, ap2 = self._three_link_active_on_one(kernel)
        aggregate = [
            s8(nl.STA_INFO_SIGNAL, 0),
            s8(nl.STA_INFO_SIGNAL_AVG, -46),
            EHT_TX,
            legacy_bitrate(nl.STA_INFO_RX_BITRATE, 3249),
            nl.attr_u32(nl.STA_INFO_RX_BYTES, 5000),
            nl.attr_u32(nl.STA_INFO_TX_BYTES, 900),
        ]
        kernel.stations = [station_message(MLD, aggregate)]
        kernel.link_stations = [
            station_message(MLD, aggregate),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        0,
                        MLD,
                        sta=[
                            s8(nl.STA_INFO_SIGNAL, 0),
                            nl.attr_u32(nl.STA_INFO_RX_BYTES, 0),
                            nl.attr_u32(nl.STA_INFO_TX_BYTES, 900),
                            nl.attr_u32(nl.STA_INFO_RX_PACKETS, 0),
                            nl.attr_u32(nl.STA_INFO_TX_PACKETS, 8),
                        ],
                    )
                ],
            ),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        1,
                        ap1,
                        sta=[
                            s8(nl.STA_INFO_SIGNAL, -45),
                            nl.attr_u32(nl.STA_INFO_RX_BYTES, 5000),
                            nl.attr_u32(nl.STA_INFO_TX_BYTES, 0),
                            nl.attr_u32(nl.STA_INFO_RX_PACKETS, 40),
                            nl.attr_u32(nl.STA_INFO_TX_PACKETS, 0),
                            legacy_bitrate(nl.STA_INFO_RX_BITRATE, 3249),
                        ],
                    )
                ],
            ),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        2,
                        ap2,
                        sta=[
                            s8(nl.STA_INFO_SIGNAL, 0),
                            nl.attr_u32(nl.STA_INFO_RX_BYTES, 0),
                            nl.attr_u32(nl.STA_INFO_TX_BYTES, 0),
                        ],
                    )
                ],
            ),
        ]
        out, iface = self.text(kernel, backend)
        requests = [msg for msg in kernel.sent if msg.cmd == nl.CMD_GET_STATION]
        assert requests
        assert all(nl.ATTR_STA_DUMP_LINK_STATS in msg.attrs for msg in requests)
        assert nl.ATTR_STA_DUMP_LINK_STATS == 367
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["tx_rate_mbps"] == 288.2
        assert info["rx_rate_mbps"] == 324.9
        assert info["signal_avg"] == -46
        assert info["rssi"] is None
        idle, active, quiet = info["links"]
        assert idle["active"] is False
        assert active["active"] is True
        assert quiet["active"] is False
        assert idle["stats"]["tx_bytes"] == 900
        assert idle["stats"]["rx_bytes"] == 0
        assert idle["stats"]["signal"] is None
        assert idle["stats"]["tx_rate"] is None
        assert idle["stats"]["signal_avg"] is None
        assert active["stats"]["rx_bytes"] == 5000
        assert active["stats"]["tx_bytes"] == 0
        assert active["stats"]["rx_packets"] == 40
        assert active["stats"]["signal"] == -45
        assert active["stats"]["signal_avg"] is None
        assert active["stats"]["tx_rate"] is None
        assert active["stats"]["rx_rate"]["mbps"] == 324.9
        assert active["stats"]["tx_retries"] is None
        assert set(active["stats"]) == {
            "signal",
            "signal_avg",
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "tx_retries",
            "tx_failed",
            "rx_rate",
            "tx_rate",
        }
        assert quiet["stats"]["rx_bytes"] == 0
        assert quiet["stats"]["signal"] is None
        assert quiet["stats"]["tx_rate"] is None
        assert "signal 0 dBm" not in out
        active_line = line(out, "Link 1 (active):")
        assert "signal -45 dBm" in active_line
        assert "rx 5000 B" in active_line
        assert "tx 0 B" in active_line
        assert "rx 324.9 Mbps" in active_line
        assert "288.2" not in active_line
        assert "signal avg" not in active_line
        assert "tx 900 B" in line(out, "Link 0:")
        assert "(active)" not in line(out, "Link 0:")

    def test_per_link_signal_zero_is_null(self, kernel, backend, tmp_path):
        backend.proc_net = str(tmp_path)
        ap1, ap2 = self._three_link_active_on_one(kernel)
        kernel.link_stations = [
            station_message(
                MLD,
                [
                    s8(nl.STA_INFO_SIGNAL, 0),
                    s8(nl.STA_INFO_SIGNAL_AVG, -46),
                ],
            ),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        0,
                        MLD,
                        sta=[
                            s8(nl.STA_INFO_SIGNAL, 0),
                            s8(nl.STA_INFO_SIGNAL_AVG, 0),
                            nl.attr_u32(nl.STA_INFO_RX_BYTES, 0),
                        ],
                    )
                ],
            ),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        1,
                        ap1,
                        sta=[s8(nl.STA_INFO_SIGNAL, -45)],
                    )
                ],
            ),
            station_message(
                MLD,
                links=[
                    mlo_link(
                        2,
                        ap2,
                        sta=[s8(nl.STA_INFO_SIGNAL, 0)],
                    )
                ],
            ),
        ]
        out, iface = self.text(kernel, backend)
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["rssi"] is None
        assert info["signal_avg"] == -46
        assert info["links"][0]["stats"]["signal"] is None
        assert info["links"][0]["stats"]["signal_avg"] == 0
        assert info["links"][0]["stats"]["rx_bytes"] == 0
        assert info["links"][1]["stats"]["signal"] == -45
        assert info["links"][2]["stats"]["signal"] is None
        assert "signal 0 dBm" not in out
        assert "signal avg 0 dBm" in line(out, "Link 0:")
        assert "signal -45 dBm" in line(out, "Link 1 (active):")
        assert "signal" not in line(out, "Link 2:")

    def test_per_link_stats_fall_back_when_the_kernel_rejects_the_flag(
        self, kernel, backend, tmp_path
    ):
        backend.proc_net = str(tmp_path)
        ap1, _ap2 = self._three_link_active_on_one(kernel)
        kernel.reject_link_stats = True
        kernel.stations = [
            station_message(
                MLD,
                [s8(nl.STA_INFO_SIGNAL, -45), EHT_TX],
                [mlo_link(0, MLD), mlo_link(1, ap1)],
            )
        ]
        iface = backend.list_interfaces()[0]
        requests_before = len(kernel.sent)
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        requests = [
            msg
            for msg in kernel.sent[requests_before:]
            if msg.cmd == nl.CMD_GET_STATION
        ]
        assert len(requests) == 2
        assert nl.ATTR_STA_DUMP_LINK_STATS in requests[0].attrs
        assert nl.ATTR_STA_DUMP_LINK_STATS not in requests[1].attrs
        assert info["channel"] == 56
        assert info["frequency_mhz"] == 5280
        assert info["tx_rate_mbps"] == 288.2
        assert info["rssi"] == -45
        assert info["links"][1]["active"] is True
        assert info["links"][0]["stats"] is None
        assert info["links"][1]["stats"] is None

    def test_watchevents_follow_the_active_link(self, kernel, backend):
        ap1, _ap2 = self._three_link_active_on_one(kernel)
        kernel.stations = [
            station_message(
                MLD,
                [s8(nl.STA_INFO_SIGNAL, 0), EHT_TX],
                [mlo_link(1, ap1, 5280)],
            )
        ]
        lines: list = []
        watcher = LinuxEventWatcher(
            backend,
            backend.list_interfaces(),
            parse(["--watchevents"]),
            emit=lines.append,
        )
        (watching,) = watcher.start()
        assert watching.record["freq_mhz"] == 5280
        assert watching.record["channel"] == 56
        assert watching.record["width_mhz"] == 20
        assert watching.record["band"] == "5 GHz"
        assert watching.record["ap_mld"] == "68:51:34:7c:32:05"
        assert "old_ap_mld" not in watching.record
        assert [item["active"] for item in watching.record["links"]] == [
            False,
            True,
            False,
        ]
        assert watching.record["links"][1]["stats"] is None

        def msg(cmd, *attrs):
            raw = event(cmd, nl.attr_u32(nl.ATTR_IFINDEX, 3) + b"".join(attrs))
            return nl.to_genl(next(nl.iter_messages(raw)))

        (idle,) = watcher.handle(
            msg(
                nl.CMD_CH_SWITCH_NOTIFY,
                nl.attr_u8(nl.ATTR_MLO_LINK_ID, 0),
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5955),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 5),
            )
        )
        assert idle.record["freq_mhz"] == 5280
        assert idle.record["channel"] == 56
        assert idle.record["width_mhz"] == 20
        assert idle.record["links"][0]["frequency_mhz"] == 5955
        assert idle.record["links"][0]["active"] is False
        assert idle.record["links"][1]["frequency_mhz"] == 5280
        assert "event: (link_channel_change)" in idle
        (moved,) = watcher.handle(
            msg(
                nl.CMD_CH_SWITCH_NOTIFY,
                nl.attr_u8(nl.ATTR_MLO_LINK_ID, 1),
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5300),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 1),
            )
        )
        assert moved.record["freq_mhz"] == 5300
        assert moved.record["channel"] == 60
        assert moved.record["width_mhz"] == 20

    def test_split_wiphy_dump_merges_channels(self, kernel, backend):
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
        ]
        kernel.stations = [station_attrs(0x21, -48, 8645)]
        kernel.wiphy_messages = [
            nl.attr_u32(nl.ATTR_WIPHY, 0)
            + nl.pack_nested(
                nl.ATTR_WIPHY_BANDS,
                [
                    band_payload(
                        nl.BAND_5GHZ,
                        [freq_attr(1, 5180)],
                        ht=True,
                        vht=True,
                        he=True,
                        eht=True,
                    )
                ],
            ),
            nl.attr_u32(nl.ATTR_WIPHY, 0)
            + nl.pack_nested(
                nl.ATTR_WIPHY_BANDS,
                [
                    band_payload(
                        nl.BAND_5GHZ,
                        [freq_attr(1, 5200), freq_attr(2, 5220)],
                    )
                ],
            ),
        ]
        out, _iface = self.text(kernel, backend)
        assert line(out, "Supported Channels:") == (
            "Supported Channels: 5 GHz 36-44 (20/40/80/160/320)"
        )
        assert line(out, "PHY:") == "PHY: HT, VHT, HE, EHT"
        dump = [message for message in kernel.sent if message.cmd == nl.CMD_GET_WIPHY][
            -1
        ]
        assert dump.flags & nl.NLM_F_DUMP
        assert nl.ATTR_SPLIT_WIPHY_DUMP in dump.attrs
        assert nl.get_uint(dump.attrs, nl.ATTR_WIPHY) == 0

    def test_channel_busy_and_supported_channels(self, kernel, backend):
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
        ]
        kernel.stations = [station_attrs(0x21, -48, 8645)]
        kernel.surveys = [
            nl.pack_nested(
                nl.ATTR_SURVEY_INFO,
                [
                    nl.attr_u32(nl.SURVEY_FREQUENCY, 2412),
                    nl.attr_u64(nl.SURVEY_TIME, 1000),
                    nl.attr_u64(nl.SURVEY_TIME_BUSY, 100),
                ],
            ),
            nl.pack_nested(
                nl.ATTR_SURVEY_INFO,
                [
                    nl.attr_u32(nl.SURVEY_FREQUENCY, 5180),
                    nl.attr_flag(nl.SURVEY_IN_USE),
                    nl.attr_u64(nl.SURVEY_TIME, 1000),
                    nl.attr_u64(nl.SURVEY_TIME_BUSY, 250),
                ],
            ),
        ]
        kernel.band_payloads = [
            band_payload(
                nl.BAND_2GHZ,
                [freq_attr(1, 2412, no_ir=True), freq_attr(2, 2462, disabled=True)],
                ht=True,
            ),
            band_payload(
                nl.BAND_5GHZ,
                [
                    freq_attr(1, 5180),
                    freq_attr(2, 5200),
                    freq_attr(3, 5220),
                    freq_attr(4, 5240),
                    freq_attr(5, 5260, radar=True),
                    freq_attr(6, 5280, radar=True),
                ],
                ht=True,
                vht=True,
            ),
            band_payload(
                nl.BAND_6GHZ, [freq_attr(1, 6135)], ht=True, he=True, eht=True
            ),
        ]
        out, iface = self.text(kernel, backend)
        assert line(out, "Channel Busy:") == "Channel Busy: 25%"
        assert line(out, "Supported Channels:") == (
            "Supported Channels: "
            "2.4 GHz 1 (20/40; no-IR), "
            "5 GHz 36-56 (20/40/80/160; DFS 52-56), "
            "6 GHz 37 (20/40/80/160/320)"
        )
        assert line(out, "PHY:") == "PHY: HT, VHT, HE, EHT"
        low, high = line(out, "Supported Channels:").split("6 GHz")
        assert "320" not in low
        assert "320" in high
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["channel_busy_percent"] == 25.0
        assert info["supported_channels"][1]["dfs"] == [[52, 56]]
        assert info["phy"] == ["HT", "VHT", "HE", "EHT"]

    def test_brcmfmac_five_ghz_keeps_standard_runs(self, kernel, backend):
        backend.sysfs.driver_name = "brcmfmac"

        def mhz(channel):
            return 5000 + 5 * channel

        standard = (
            list(range(36, 65, 4)) + list(range(100, 145, 4)) + list(range(149, 166, 4))
        )
        extra = [34, 38, 42, 46]
        radar = set(range(52, 65, 4)) | set(range(100, 145, 4))
        freqs = [
            freq_attr(index, mhz(channel), radar=channel in radar)
            for index, channel in enumerate(extra + standard, start=1)
        ]
        kernel.interfaces = [
            iface_attrs(3, "wlan0", freq=5180, width=1, center1=5180, tx_mbm=None)
        ]
        kernel.band_payloads = [band_payload(nl.BAND_5GHZ, freqs, ht=True, vht=True)]
        out, iface = self.text(kernel, backend)
        assert line(out, "Supported Channels:") == (
            "Supported Channels: 5 GHz 36-64, 100-144, 149-165 "
            "(also 34, 38, 42, 46) (20/40/80/160; DFS 52-64, 100-144)"
        )
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["supported_channels"][0]["ranges"] == [
            [34, 34],
            [36, 36],
            [38, 38],
            [40, 40],
            [42, 42],
            [44, 44],
            [46, 46],
            [48, 64],
            [100, 144],
            [149, 165],
        ]
        assert info["supported_channels"][0]["dfs"] == [[52, 64], [100, 144]]

    def test_standard_five_ghz_runs(self, kernel, backend):
        def mhz(channel):
            return 5000 + 5 * channel

        standard = (
            list(range(36, 65, 4)) + list(range(100, 145, 4)) + list(range(149, 166, 4))
        )
        radar = set(range(52, 65, 4)) | set(range(100, 145, 4))
        freqs = [
            freq_attr(index, mhz(channel), radar=channel in radar)
            for index, channel in enumerate(standard, start=1)
        ]
        kernel.interfaces = [
            iface_attrs(3, "wlan0", freq=5180, width=1, center1=5180, tx_mbm=None)
        ]
        kernel.band_payloads = [band_payload(nl.BAND_5GHZ, freqs, ht=True, vht=True)]
        out, iface = self.text(kernel, backend)
        assert line(out, "Supported Channels:") == (
            "Supported Channels: 5 GHz 36-64, 100-144, 149-165 "
            "(20/40/80/160; DFS 52-64, 100-144)"
        )
        assert "(also" not in out
        info = json.loads(
            backend.interface_info(parse(["--get-interfaces", "--json"]), iface)
        )
        assert info["supported_channels"][0]["ranges"] == [
            [36, 64],
            [100, 144],
            [149, 165],
        ]
        assert info["supported_channels"][0]["dfs"] == [[52, 64], [100, 144]]

    def test_missing_survey_wiphy_and_station_attrs(self, kernel, backend, caplog):
        kernel.interfaces = [
            iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
        ]
        kernel.stations = [station_message(mac(0x21), [s8(nl.STA_INFO_SIGNAL, -40)])]
        kernel.survey_error = errno.EOPNOTSUPP
        kernel.wiphy_error = errno.EOPNOTSUPP
        out, _iface = self.text(kernel, backend)
        assert line(out, "RSSI:") == "RSSI: -40 dBm"
        assert "Transmit (Tx) Rate:" not in out
        assert "Channel Busy" not in out
        assert "Supported Channels" not in out
        assert "PHY:" not in out
        assert "WARNING" not in caplog.text


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
        assert "old_ap_mld" not in lines[0].record
        assert "ap_mld" not in lines[0].record
        assert "links" not in lines[0].record

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
        assert line.record["old_ap_mld"] is None
        assert "old_ap_mld:" not in line
        assert "ap_mld" not in line.record
        assert line.record["freq_mhz"] == 5975

    def test_connect_and_failure(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        (ok,) = watcher.handle(
            self.msg(nl.CMD_CONNECT, nl.attr_u16(nl.ATTR_STATUS_CODE, 0))
        )
        assert "event: (connected)" in ok
        assert ok.record["old_ap_mld"] is None
        assert "old_ap_mld:" not in ok
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
        assert "event: (channel_change)" in line

    def test_channel_switch_started_without_link_is_ignored(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        assert (
            watcher.handle(
                self.msg(
                    nl.CMD_CH_SWITCH_STARTED_NOTIFY,
                    nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5500),
                    nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 5),
                )
            )
            == []
        )

    def _two_link(self, kernel, tx_units=2882):
        active = bytes.fromhex("a6b1f5a21e29")
        quiet = bytes.fromhex("7ae3a942cd3a")
        link2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"wlanpiwlanpi",
                freq=None,
                links=[
                    mlo_link(0, active, 6135, width=3, center1=6145, tx_mbm=2200),
                    mlo_link(2, quiet),
                ],
                last=0x63,
            )
        ]
        tx = (
            EHT_TX
            if tx_units == 2882
            else legacy_bitrate(nl.STA_INFO_TX_BITRATE, tx_units)
        )
        kernel.stations = [
            station_message(
                MLD,
                [
                    s8(nl.STA_INFO_SIGNAL, 0),
                    tx,
                    legacy_bitrate(nl.STA_INFO_RX_BITRATE, 240),
                ],
                [mlo_link(0, MLD, 6135), mlo_link(2, link2, 2462)],
            )
        ]

    def test_two_link_mlo_watch_and_connect(self, kernel, backend):
        self._two_link(kernel)
        lines: list = []
        watcher = LinuxEventWatcher(
            backend,
            backend.list_interfaces(),
            parse(["--watchevents"]),
            emit=lines.append,
        )
        (watching,) = watcher.start()
        assert "freq: (None)" not in watching
        assert "rssi:" not in watching
        assert "channel: ()" not in watching
        assert watching == (
            "(02:00:00:00:00:63), ap_mld: (68:51:34:7c:32:05), freq: (6135), "
            "ssid: (wlanpiwlanpi), event: (watching), channel: (37@80 6 GHz), "
            "tx_rate: (288.2 Mbps), "
            "links: (0: 68:51:34:7c:32:05 6 GHz ch 37@80, "
            "2: 68:51:34:7c:31:f5 2.4 GHz ch 11)"
        )
        assert watching.record["freq_mhz"] == 6135
        assert watching.record["channel"] == 37
        assert watching.record["width_mhz"] == 80
        assert watching.record["band"] == "6 GHz"
        assert watching.record["rssi"] is None
        assert watching.record["ap_mld"] == "68:51:34:7c:32:05"
        assert watching.record["links"][0]["bssid"] == "68:51:34:7c:32:05"
        assert watching.record["links"][1]["channel"] == 11
        assert "width_mhz" not in watching.record["links"][1]
        assert '"rssi": null' in dumps(
            watching.record, timestamp="2026-01-01T00:00:00.000+00:00"
        )

        self._two_link(kernel, tx_units=688)
        (connected,) = watcher.handle(
            self.msg(nl.CMD_CONNECT, nl.attr_u16(nl.ATTR_STATUS_CODE, 0))
        )
        assert "event: (connected)" in connected
        assert "freq: (6135)" in connected
        assert "channel: (37@80 6 GHz)" in connected
        assert "tx_rate: (68.8 Mbps)" in connected
        assert "rssi:" not in connected
        assert "links: (0: 68:51:34:7c:32:05 6 GHz ch 37@80, " in connected
        assert connected.record["rssi"] is None
        assert connected.record["freq_mhz"] == 6135
        assert connected.record["old_ap_mld"] is None
        assert "old_ap_mld:" not in connected

    def test_bss_dump_links_in_watchevents(self, kernel, backend):
        active = bytes.fromhex("a6b1f5a21e29")
        quiet = bytes.fromhex("7ae3a942cd3a")
        link2 = bytes.fromhex("6851347c31f5")
        kernel.interfaces = [
            iface_attrs(
                3,
                "wlan0",
                ssid=b"wlanpiwlanpi",
                freq=None,
                links=[
                    mlo_link(0, active, 6135, width=3, center1=6145, tx_mbm=2200),
                    mlo_link(2, quiet),
                ],
                last=0x63,
            )
        ]
        kernel.stations = [station_message(MLD, [s8(nl.STA_INFO_SIGNAL, 0), EHT_TX])]
        kernel.bss = [
            associated_bss(MLD, 6135, 0, MLD),
            associated_bss(link2, 2462, 2, MLD),
        ]
        lines: list = []
        watcher = LinuxEventWatcher(
            backend,
            backend.list_interfaces(),
            parse(["--watchevents"]),
            emit=lines.append,
        )
        (watching,) = watcher.start()
        assert watching == (
            "(02:00:00:00:00:63), ap_mld: (68:51:34:7c:32:05), freq: (6135), "
            "ssid: (wlanpiwlanpi), event: (watching), channel: (37@80 6 GHz), "
            "tx_rate: (288.2 Mbps), "
            "links: (0: 68:51:34:7c:32:05 6 GHz ch 37@80, "
            "2: 68:51:34:7c:31:f5 2.4 GHz ch 11)"
        )
        assert watching.record["ap_mld"] == "68:51:34:7c:32:05"
        assert watching.record["links"][1]["bssid"] == "68:51:34:7c:31:f5"
        assert watching.record["links"][1]["frequency_mhz"] == 2462
        assert watching.record["links"][1]["channel"] == 11
        assert watching.record["links"][1]["band"] == "2.4 GHz"
        assert watching.record["links"][0]["addr"] == "a6:b1:f5:a2:1e:29"

    def _watch(self, kernel, backend):
        lines: list = []
        watcher = LinuxEventWatcher(
            backend,
            backend.list_interfaces(),
            parse(["--watchevents"]),
            emit=lines.append,
        )
        lines.extend(watcher.start())
        return watcher, lines

    def test_mlo_link_channel_switch_is_not_the_whole_connection(self, kernel, backend):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        (line,) = watcher.handle(
            self.msg(
                nl.CMD_CH_SWITCH_NOTIFY,
                nl.attr_u8(nl.ATTR_MLO_LINK_ID, 2),
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 2412),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 1),
            )
        )
        assert "event: (link_channel_change)" in line
        assert "event: (channel_change)" not in line
        assert "event: (roamed)" not in line
        assert "freq: (6135)" in line
        assert "freq: (2412)" not in line
        assert "link: (2: 68:51:34:7c:31:f5 2.4 GHz ch 1@20)" in line
        assert "old_link: (2: 68:51:34:7c:31:f5 2.4 GHz ch 11)" in line
        assert line.record["link"][0]["id"] == 2
        assert line.record["link"][0]["frequency_mhz"] == 2412
        assert line.record["old_link"][0]["channel"] == 11
        assert line.record["freq_mhz"] == 6135
        stored = watcher.formatters[3].last.extra["links"]
        assert stored[1]["frequency_mhz"] == 2412
        assert stored[0]["frequency_mhz"] == 6135
        (moved,) = watcher.handle(
            self.msg(
                nl.CMD_CH_SWITCH_NOTIFY,
                nl.attr_u8(nl.ATTR_MLO_LINK_ID, 0),
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5955),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 3),
            )
        )
        assert "event: (link_channel_change)" in moved
        assert "event: (channel_change)" not in moved
        assert "freq: (5955)" in moved
        assert "link: (0: 68:51:34:7c:32:05 6 GHz ch 1@80)" in moved

    def test_mlo_link_channel_switch_started_does_not_move_the_link(
        self, kernel, backend
    ):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        (line,) = watcher.handle(
            self.msg(
                nl.CMD_CH_SWITCH_STARTED_NOTIFY,
                nl.attr_u8(nl.ATTR_MLO_LINK_ID, 0),
                nl.attr_u32(nl.ATTR_WIPHY_FREQ, 5955),
                nl.attr_u32(nl.ATTR_CHANNEL_WIDTH, 3),
            )
        )
        assert "event: (link_channel_switch_started)" in line
        assert "event: (channel_change)" not in line
        assert "event: (roamed)" not in line
        assert "freq: (6135)" in line
        assert "link: (0: 68:51:34:7c:32:05 6 GHz ch 1@80)" in line
        assert watcher.formatters[3].last.frequency_mhz == 6135
        assert watcher.formatters[3].last.extra["links"][0]["frequency_mhz"] == 6135

    def test_mlo_link_removed_and_added(self, kernel, backend):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        (removed,) = watcher.handle(
            self.msg(
                nl.CMD_LINKS_REMOVED,
                nl.pack_nested(
                    nl.ATTR_MLO_LINKS,
                    [nl.pack_nested(1, [nl.attr_u8(nl.ATTR_MLO_LINK_ID, 2)])],
                ),
            )
        )
        assert "event: (link_removed)" in removed
        assert "event: (roamed)" not in removed
        assert "event: (disconnected)" not in removed
        assert "link: (2: 68:51:34:7c:31:f5 2.4 GHz ch 11)" in removed
        assert removed.split("links:", 1)[1] == (
            " (0: 68:51:34:7c:32:05 6 GHz ch 37@80)"
        )
        assert removed.record["link"][0]["id"] == 2
        assert [item["id"] for item in removed.record["links"]] == [0]
        assert removed.record["ap_mld"] == "68:51:34:7c:32:05"
        assert "mld" not in removed.record
        stored = watcher.formatters[3].last.extra["links"]
        assert [item["id"] for item in stored] == [0]

        watcher.scan_events = True
        (cached,) = watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS))
        assert "event: (scan_cache_updated)" in cached
        assert cached.split("links:", 1)[1] == (
            " (0: 68:51:34:7c:32:05 6 GHz ch 37@80)"
        )
        assert [item["id"] for item in cached.record["links"]] == [0]

        other = bytes.fromhex("6851347c3206")
        (added,) = watcher.handle(
            self.msg(
                nl.CMD_ASSOC_MLO_RECONF,
                nl.pack_nested(nl.ATTR_MLO_LINKS, [mlo_link(1, other, 5210)]),
            )
        )
        assert "event: (link_added)" in added
        assert "event: (roamed)" not in added
        assert "link: (1: 68:51:34:7c:32:06 5 GHz ch 42)" in added
        assert added.record["link"][0]["id"] == 1
        assert added.record["link"][0]["frequency_mhz"] == 5210
        assert (
            watcher.handle(
                self.msg(
                    nl.CMD_ASSOC_MLO_RECONF,
                    nl.attr_u16(nl.ATTR_STATUS_CODE, 1),
                    nl.pack_nested(nl.ATTR_MLO_LINKS, [mlo_link(1, other, 5210)]),
                )
            )
            == []
        )

    def test_mlo_disconnect_keeps_ap_mld(self, kernel, backend):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        (line,) = watcher.handle(
            self.msg(
                nl.CMD_DISCONNECT,
                nl.attr_u16(nl.ATTR_REASON_CODE, 3),
                nl.attr_flag(nl.ATTR_DISCONNECTED_BY_AP),
            )
        )
        assert "ap_mld: (68:51:34:7c:32:05)" in line
        assert "bssid:" not in line
        assert "event: (disconnected)" in line
        assert line.record["ap_mld"] == "68:51:34:7c:32:05"
        assert line.record["bssid"] == "68:51:34:7c:32:05"
        assert "mld" not in line.record
        assert "old_ap_mld" not in line.record

    def test_old_ap_mld_on_roam_and_reconnect(self, kernel, backend):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        new_mld = bytes.fromhex("6851347c32aa")
        kernel.stations = [
            station_message(
                new_mld,
                [
                    s8(nl.STA_INFO_SIGNAL, -50),
                    legacy_bitrate(nl.STA_INFO_TX_BITRATE, 688),
                ],
            )
        ]
        (roamed,) = watcher.handle(
            self.msg(nl.CMD_ROAM, nl.pack_attr(nl.ATTR_MAC, new_mld))
        )
        assert roamed.record["bssid"] == "68:51:34:7c:32:aa"
        assert roamed.record["old_bssid"] == "68:51:34:7c:32:05"
        assert roamed.record["old_ap_mld"] == "68:51:34:7c:32:05"
        assert "old_ap_mld: (68:51:34:7c:32:05)" in roamed
        assert "old_bssid: (68:51:34:7c:32:05)" in roamed
        assert '"old_ap_mld": "68:51:34:7c:32:05"' in dumps(
            roamed.record, timestamp="2026-01-01T00:00:00.000+00:00"
        )

        self._two_link(kernel)
        (back,) = watcher.handle(self.msg(nl.CMD_ROAM, nl.pack_attr(nl.ATTR_MAC, MLD)))
        assert back.record["old_bssid"] == "68:51:34:7c:32:aa"
        assert back.record["old_ap_mld"] == "68:51:34:7c:32:aa"
        assert "old_ap_mld: (68:51:34:7c:32:aa)" in back

        (gone,) = watcher.handle(
            self.msg(
                nl.CMD_DISCONNECT,
                nl.attr_u16(nl.ATTR_REASON_CODE, 3),
            )
        )
        assert "old_ap_mld" not in gone.record
        kernel.stations = [station_message(new_mld, [s8(nl.STA_INFO_SIGNAL, -55)])]
        (connected,) = watcher.handle(
            self.msg(nl.CMD_CONNECT, nl.attr_u16(nl.ATTR_STATUS_CODE, 0))
        )
        assert connected.record["old_bssid"] == "68:51:34:7c:32:05"
        assert connected.record["old_ap_mld"] == "68:51:34:7c:32:05"
        assert connected.record["bssid"] == "68:51:34:7c:32:aa"
        assert "old_ap_mld: (68:51:34:7c:32:05)" in connected
        assert '"old_ap_mld": "68:51:34:7c:32:05"' in dumps(
            connected.record, timestamp="2026-01-01T00:00:00.000+00:00"
        )

    def test_connect_failed_keeps_previous_ap_mld(self, kernel, backend):
        self._two_link(kernel)
        watcher, _lines = self._watch(kernel, backend)
        (gone,) = watcher.handle(
            self.msg(
                nl.CMD_DISCONNECT,
                nl.attr_u16(nl.ATTR_REASON_CODE, 3),
            )
        )
        assert gone.record["ap_mld"] == "68:51:34:7c:32:05"
        (failed,) = watcher.handle(
            self.msg(
                nl.CMD_CONNECT,
                nl.pack_attr(nl.ATTR_MAC, mac(0x44)),
                nl.attr_u16(nl.ATTR_STATUS_CODE, 17),
            )
        )
        assert "event: (connect_failed)" in failed
        assert failed.record["bssid"] == "02:00:00:00:00:44"
        assert "old_ap_mld" not in failed.record
        new_mld = bytes.fromhex("6851347c32aa")
        kernel.stations = [station_message(new_mld, [s8(nl.STA_INFO_SIGNAL, -55)])]
        (connected,) = watcher.handle(
            self.msg(nl.CMD_CONNECT, nl.attr_u16(nl.ATTR_STATUS_CODE, 0))
        )
        assert connected.record["bssid"] == "68:51:34:7c:32:aa"
        assert connected.record["old_bssid"] == "68:51:34:7c:32:05"
        assert connected.record["old_ap_mld"] == "68:51:34:7c:32:05"

    def test_missing_fields_are_hidden_and_json_null(self):
        formatter = LinkFormatter("02:00:00:00:00:13")
        line = formatter.watching(
            LinkInfo(
                connected=True,
                bssid="02:00:00:00:00:21",
                ssid=b"ExampleNet",
                rssi=0,
            )
        )
        assert "freq:" not in line
        assert "channel:" not in line
        assert "rssi: (0)" in line
        assert line.record["freq_mhz"] is None
        assert line.record["rssi"] == 0
        assert line.record["channel"] is None
        assert line.record["width_mhz"] is None
        assert line.record["band"] is None

    def test_scan_results_only_with_debug(self, kernel, backend):
        watcher, _ = self.watcher(kernel, backend)
        assert watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS)) == []
        watcher, _ = self.watcher(kernel, backend, ("--watchevents", "--debug"))
        (line,) = watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS))
        assert "scan: (1 BSSIDs found)" in line

    def test_scan_dump_failure_does_not_stop_watch(self, kernel, backend, monkeypatch):
        watcher, _ = self.watcher(kernel, backend, ("--watchevents", "--debug"))

        def gone(native):
            raise BackendError("reading scan results failed on wlan1: No such device")

        monkeypatch.setattr(backend, "dump_scan", gone)
        assert watcher.handle(self.msg(nl.CMD_NEW_SCAN_RESULTS)) == []

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


def test_get_interfaces_json_writes_the_file(kernel, backend, tmp_path, capsys):
    from lswifi import app

    kernel.interfaces = [
        iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
    ]
    kernel.stations = [station_attrs(0x21, -48, 8645)]
    path = tmp_path / "iface.json"
    with pytest.raises(SystemExit):
        app.run(parse(["--get-interfaces", "--json", str(path)]), backend=backend)
    printed = json.loads(capsys.readouterr().out)
    saved = json.loads(path.read_text())
    assert printed["bssid"] == saved["bssid"] == "02:00:00:00:00:21"
    assert saved["channel"] == 36
    assert saved["ssid"] == "ExampleNet"


def test_bare_get_interfaces_json_stays_on_stdout(
    kernel, backend, tmp_path, capsys, monkeypatch
):
    from lswifi import app

    monkeypatch.chdir(tmp_path)
    kernel.interfaces = [
        iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13)
    ]
    kernel.stations = [station_attrs(0x21, -48, 8645)]
    with pytest.raises(SystemExit):
        app.run(parse(["--get-interfaces", "--json"]), backend=backend)
    shown = json.loads(capsys.readouterr().out)
    assert shown["ssid"] == "ExampleNet"
    assert list(tmp_path.glob("*.json")) == []


def test_two_interfaces_json_is_one_document(kernel, backend, tmp_path, capsys):
    from lswifi import app

    kernel.interfaces = [
        iface_attrs(3, "wlan0", ssid=b"ExampleNet", freq=5180, last=0x13),
        iface_attrs(4, "wlan1", ssid=b"Other", freq=2412, width=1, last=0x14),
    ]
    kernel.stations = [station_attrs(0x21, -48, 8645)]
    path = tmp_path / "ifaces.json"
    with pytest.raises(SystemExit):
        app.run(parse(["--get-interfaces", "--json", str(path)]), backend=backend)
    printed = json.loads(capsys.readouterr().out)
    saved = json.loads(path.read_text())
    assert printed == saved
    assert [item["interface"] for item in printed] == ["wlan0", "wlan1"]

    capsys.readouterr()
    with pytest.raises(SystemExit):
        app.run(parse(["--get-interfaces", "--json"]), backend=backend)
    bare = json.loads(capsys.readouterr().out)
    assert [item["interface"] for item in bare] == ["wlan0", "wlan1"]


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
        by_bssid = {row["bssid"]: row["rssi"] for row in json_out}
        assert by_bssid["02:00:00:00:00:31"] == "--"
        assert by_bssid["02:00:00:00:00:32"] == "-40"
        assert len(out) == 2
