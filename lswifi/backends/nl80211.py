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
lswifi.backends.nl80211
~~~~~~~~~~~~~~~~~~~~~~~

a small stdlib-only nl80211 client: generic netlink over AF_NETLINK, plus
the constants and attribute helpers the Linux backend needs.

constants are from include/uapi/linux/nl80211.h and genetlink.h. message
building and parsing are plain functions so tests can feed synthetic kernel
replies through a fake socket on any OS.
"""

import contextlib
import errno
import os
import select
import socket
import struct
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

# netlink / generic netlink
NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NETLINK_CAP_ACK = 10
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x1
NLM_F_MULTI = 0x2
NLM_F_ACK = 0x4
NLM_F_DUMP = 0x300
NLA_F_NESTED = 0x8000
NLA_TYPE_MASK = 0x3FFF
NLMSG_HDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
GENL_HDR = struct.Struct("=BBH")  # cmd, version, reserved
NLA_HDR = struct.Struct("=HH")  # len, type

GENL_ID_CTRL = 0x10
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

# nl80211 commands
CMD_GET_INTERFACE = 5
CMD_NEW_INTERFACE = 7
CMD_GET_STATION = 17
CMD_NEW_STATION = 19
CMD_GET_REG = 31
CMD_GET_SCAN = 32
CMD_TRIGGER_SCAN = 33
CMD_NEW_SCAN_RESULTS = 34
CMD_SCAN_ABORTED = 35
CMD_AUTHENTICATE = 37
CMD_ASSOCIATE = 38
CMD_DEAUTHENTICATE = 39
CMD_DISASSOCIATE = 40
CMD_CONNECT = 46
CMD_ROAM = 47
CMD_DISCONNECT = 48
CMD_CH_SWITCH_NOTIFY = 88
CMD_PORT_AUTHORIZED = 125

# nl80211 attributes
ATTR_WIPHY = 1
ATTR_IFINDEX = 3
ATTR_IFNAME = 4
ATTR_IFTYPE = 5
ATTR_MAC = 6
ATTR_STA_INFO = 21
ATTR_REG_ALPHA2 = 33
ATTR_WIPHY_FREQ = 38
ATTR_SCAN_SSIDS = 45
ATTR_BSS = 47
ATTR_SSID = 52
ATTR_REASON_CODE = 54
ATTR_TIMED_OUT = 65
ATTR_DISCONNECTED_BY_AP = 71
ATTR_STATUS_CODE = 72
ATTR_WIPHY_TX_POWER_LEVEL = 98
ATTR_WDEV = 153
ATTR_CHANNEL_WIDTH = 159
ATTR_CENTER_FREQ1 = 160

# NL80211_BSS_*, nested in ATTR_BSS
BSS_BSSID = 1
BSS_FREQUENCY = 2
BSS_TSF = 3
BSS_BEACON_INTERVAL = 4
BSS_CAPABILITY = 5
BSS_INFORMATION_ELEMENTS = 6
BSS_SIGNAL_MBM = 7
BSS_SIGNAL_UNSPEC = 8
BSS_STATUS = 9
BSS_SEEN_MS_AGO = 10
BSS_BEACON_IES = 11
BSS_CHAN_WIDTH = 12
BSS_BEACON_TSF = 13
BSS_PRESP_DATA = 14
BSS_LAST_SEEN_BOOTTIME = 15

BSS_STATUS_AUTHENTICATED = 0
BSS_STATUS_ASSOCIATED = 1
BSS_STATUS_IBSS_JOINED = 2

# NL80211_BSS_CHAN_WIDTH_*
BSS_CHAN_WIDTH_MHZ = {0: 20, 1: 10, 2: 5}

# NL80211_STA_INFO_* and NL80211_RATE_INFO_*
STA_INFO_SIGNAL = 7
STA_INFO_TX_BITRATE = 8
RATE_INFO_BITRATE = 1  # u16, 100 kbit/s
RATE_INFO_BITRATE32 = 5  # u32, 100 kbit/s

IFTYPE_ADHOC = 1
IFTYPE_STATION = 2
IFTYPE_AP = 3
IFTYPE_MONITOR = 6
IFTYPE_P2P_CLIENT = 8
IFTYPE_NAMES = {
    0: "unspecified",
    1: "IBSS",
    2: "managed",
    3: "AP",
    4: "AP/VLAN",
    5: "WDS",
    6: "monitor",
    7: "mesh point",
    8: "P2P-client",
    9: "P2P-GO",
    10: "P2P-device",
    11: "outside context of a BSS",
    12: "NAN",
}

# NL80211_CHAN_WIDTH_* to MHz (20_NOHT and 20 are both 20; 80P80 is 160)
CHAN_WIDTH_MHZ = {0: 20, 1: 20, 2: 40, 3: 80, 4: 160, 5: 160, 6: 5, 7: 10, 13: 320}

MCAST_GROUP_SCAN = "scan"
MCAST_GROUP_MLME = "mlme"

RECV_SIZE = 1 << 20


class NetlinkError(OSError):
    """An NLMSG_ERROR reply with a non-zero error"""

    def __init__(self, code: int, context: str = "") -> None:
        message = os.strerror(code)
        if context:
            message = f"{context}: {message}"
        super().__init__(code, message)


# --- attributes -----------------------------------------------------------


def align4(length: int) -> int:
    return (length + 3) & ~3


def pack_attr(kind: int, payload: bytes) -> bytes:
    length = NLA_HDR.size + len(payload)
    return NLA_HDR.pack(length, kind) + payload + b"\0" * (align4(length) - length)


def pack_nested(kind: int, attrs: Iterable[bytes]) -> bytes:
    return pack_attr(kind | NLA_F_NESTED, b"".join(attrs))


def attr_u8(kind: int, value: int) -> bytes:
    return pack_attr(kind, struct.pack("=B", value))


def attr_u16(kind: int, value: int) -> bytes:
    return pack_attr(kind, struct.pack("=H", value))


def attr_u32(kind: int, value: int) -> bytes:
    return pack_attr(kind, struct.pack("=I", value))


def attr_s32(kind: int, value: int) -> bytes:
    return pack_attr(kind, struct.pack("=i", value))


def attr_u64(kind: int, value: int) -> bytes:
    return pack_attr(kind, struct.pack("=Q", value))


def attr_str(kind: int, value: str) -> bytes:
    return pack_attr(kind, value.encode() + b"\0")


def attr_flag(kind: int) -> bytes:
    return pack_attr(kind, b"")


def iter_attrs(data: bytes) -> Iterator[tuple[int, bytes]]:
    """(type, payload) for each attribute; stops at a truncated one"""
    offset = 0
    while offset + NLA_HDR.size <= len(data):
        length, kind = NLA_HDR.unpack_from(data, offset)
        if length < NLA_HDR.size or offset + length > len(data):
            return
        yield kind & NLA_TYPE_MASK, data[offset + NLA_HDR.size : offset + length]
        offset += align4(length)


def parse_attrs(data: bytes) -> dict[int, bytes]:
    return dict(iter_attrs(data))


def get_uint(
    attrs: dict[int, bytes], kind: int, default: int | None = None
) -> int | None:
    """u8/u16/u32/u64 by payload size, host byte order"""
    raw = attrs.get(kind)
    if raw is None:
        return default
    fmt = {1: "=B", 2: "=H", 4: "=I", 8: "=Q"}.get(len(raw))
    if fmt is None:
        return default
    return int(struct.unpack(fmt, raw)[0])


def get_int(
    attrs: dict[int, bytes], kind: int, default: int | None = None
) -> int | None:
    """s8/s16/s32/s64 by payload size, host byte order"""
    raw = attrs.get(kind)
    if raw is None:
        return default
    fmt = {1: "=b", 2: "=h", 4: "=i", 8: "=q"}.get(len(raw))
    if fmt is None:
        return default
    return int(struct.unpack(fmt, raw)[0])


def get_str(attrs: dict[int, bytes], kind: int) -> str | None:
    raw = attrs.get(kind)
    if raw is None:
        return None
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def mac_str(raw: bytes | None) -> str:
    if not raw or len(raw) != 6:
        return ""
    return ":".join(f"{octet:02x}" for octet in raw)


# --- messages -------------------------------------------------------------


@dataclass
class GenlMessage:
    """One generic netlink message: nlmsghdr + genlmsghdr + attributes"""

    type: int
    flags: int
    seq: int
    pid: int
    cmd: int
    attrs: dict[int, bytes] = field(default_factory=dict)


def build_message(
    family: int,
    cmd: int,
    attrs: bytes = b"",
    flags: int = NLM_F_REQUEST | NLM_F_ACK,
    seq: int = 0,
    pid: int = 0,
    version: int = 1,
) -> bytes:
    payload = GENL_HDR.pack(cmd, version, 0) + attrs
    return (
        NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), family, flags, seq, pid) + payload
    )


def build_error(seq: int, code: int, pid: int = 0) -> bytes:
    """NLMSG_ERROR; code 0 is an ACK, otherwise a negative errno"""
    payload = struct.pack("=i", code) + NLMSG_HDR.pack(NLMSG_HDR.size, 0, 0, seq, pid)
    return (
        NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), NLMSG_ERROR, 0, seq, pid)
        + payload
    )


def build_done(seq: int, pid: int = 0) -> bytes:
    payload = struct.pack("=i", 0)
    return (
        NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), NLMSG_DONE, NLM_F_MULTI, seq, pid)
        + payload
    )


@dataclass
class RawMessage:
    type: int
    flags: int
    seq: int
    pid: int
    payload: bytes


def iter_messages(data: bytes) -> Iterator[RawMessage]:
    offset = 0
    while offset + NLMSG_HDR.size <= len(data):
        length, kind, flags, seq, pid = NLMSG_HDR.unpack_from(data, offset)
        if length < NLMSG_HDR.size or offset + length > len(data):
            return
        yield RawMessage(
            kind, flags, seq, pid, data[offset + NLMSG_HDR.size : offset + length]
        )
        offset += align4(length)


def to_genl(message: RawMessage) -> GenlMessage:
    cmd = message.payload[0] if message.payload else 0
    return GenlMessage(
        message.type,
        message.flags,
        message.seq,
        message.pid,
        cmd,
        parse_attrs(message.payload[GENL_HDR.size :]),
    )


def error_code(message: RawMessage) -> int:
    """errno (positive) of an NLMSG_ERROR, 0 for an ACK"""
    if len(message.payload) < 4:
        return 0
    return -int(struct.unpack_from("=i", message.payload)[0])


# --- socket ---------------------------------------------------------------


class NetlinkSocket(Protocol):
    def send(self, data: bytes, /) -> int: ...

    def recv(self, bufsize: int, /) -> bytes: ...

    def setsockopt(self, level: int, option: int, value: int, /) -> None: ...

    def fileno(self) -> int: ...

    def close(self) -> None: ...


def open_socket() -> Any:
    """A bound NETLINK_GENERIC socket. Linux only."""
    family = getattr(socket, "AF_NETLINK", None)
    if family is None:
        raise OSError(errno.EAFNOSUPPORT, "AF_NETLINK is not available on this OS")
    sock = socket.socket(family, socket.SOCK_RAW, NETLINK_GENERIC)
    try:
        sock.bind((0, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECV_SIZE)
        # do not echo the request back in error replies
        with contextlib.suppress(OSError):
            sock.setsockopt(SOL_NETLINK, NETLINK_CAP_ACK, 1)
    except OSError:
        sock.close()
        raise
    return sock


def _wait_readable(sock: Any, timeout: float | None) -> bool:
    pending = getattr(sock, "pending", None)
    if callable(pending):  # in-memory test socket; no fd to select on
        return bool(pending())
    if timeout is None:
        return True
    readable, _, _ = select.select([sock], [], [], max(0.0, timeout))
    return bool(readable)


class GenericNetlink:
    """Request/response and multicast on one generic netlink socket.

    Use one instance for requests and a separate one for multicast events,
    so notifications never interleave with a dump.
    """

    def __init__(self, sock: Any = None, family_name: str = "nl80211") -> None:
        self.sock = sock if sock is not None else open_socket()
        self.seq = int(time.time()) & 0x7FFFFFFF
        self.family_name = family_name
        self.family_id = 0
        self.groups: dict[str, int] = {}
        try:
            self._resolve_family()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()

    def __enter__(self) -> "GenericNetlink":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0x7FFFFFFF
        return self.seq

    def _resolve_family(self) -> None:
        replies = self._request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            attr_str(CTRL_ATTR_FAMILY_NAME, self.family_name),
            dump=False,
        )
        for reply in replies:
            family_id = get_uint(reply.attrs, CTRL_ATTR_FAMILY_ID)
            if family_id is None:
                continue
            self.family_id = family_id
            for _index, group in iter_attrs(
                reply.attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")
            ):
                group_attrs = parse_attrs(group)
                name = get_str(group_attrs, CTRL_ATTR_MCAST_GRP_NAME)
                group_id = get_uint(group_attrs, CTRL_ATTR_MCAST_GRP_ID)
                if name and group_id is not None:
                    self.groups[name] = group_id
            return
        raise OSError(
            errno.ENOENT, f"generic netlink family {self.family_name} not found"
        )

    def _request(
        self, family: int, cmd: int, attrs: bytes, dump: bool, timeout: float = 10.0
    ) -> list[GenlMessage]:
        seq = self._next_seq()
        flags = NLM_F_REQUEST | (NLM_F_DUMP if dump else NLM_F_ACK)
        self.sock.send(build_message(family, cmd, attrs, flags=flags, seq=seq))
        replies: list[GenlMessage] = []
        deadline = time.monotonic() + timeout
        while True:
            if not _wait_readable(self.sock, deadline - time.monotonic()):
                raise OSError(errno.ETIMEDOUT, "no reply from nl80211")
            data = self.sock.recv(RECV_SIZE)
            for message in iter_messages(data):
                if message.seq != seq:
                    continue  # stale reply to an earlier request
                if message.type == NLMSG_ERROR:
                    code = error_code(message)
                    if code:
                        raise NetlinkError(code)
                    return replies  # ACK
                if message.type == NLMSG_DONE:
                    if code := error_code(message):  # a dump that failed midway
                        raise NetlinkError(code)
                    return replies
                replies.append(to_genl(message))

    def request(
        self, cmd: int, attrs: bytes = b"", dump: bool = False
    ) -> list[GenlMessage]:
        return self._request(self.family_id, cmd, attrs, dump)

    def join(self, *names: str) -> None:
        """Subscribe to nl80211 multicast groups"""
        for name in names:
            group_id = self.groups.get(name)
            if group_id is None:
                raise OSError(
                    errno.ENOENT, f"nl80211 multicast group {name!r} not found"
                )
            self.sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group_id)

    def events(self, timeout: float | None = None) -> list[GenlMessage]:
        """Multicast messages that arrive within timeout (None blocks)"""
        if not _wait_readable(self.sock, timeout):
            return []
        data = self.sock.recv(RECV_SIZE)
        return [
            to_genl(message)
            for message in iter_messages(data)
            if message.type == self.family_id
        ]


__all__ = [
    "GenericNetlink",
    "GenlMessage",
    "NetlinkError",
    "build_message",
    "iter_attrs",
    "parse_attrs",
]
