# -*- encoding: utf-8

import pytest
from unittest.mock import MagicMock

from lswifi import slog


class TestSlog:
    def test_syslog_level_dict(self):
        """Verify syslog level mapping."""
        assert slog.SYSLOG_LEVEL["DEBUG"] == "7"
        assert slog.SYSLOG_LEVEL["INFO"] == "6"
        assert slog.SYSLOG_LEVEL["ERROR"] == "3"
        assert slog.SYSLOG_LEVEL["WARN"] == "4"
        assert slog.SYSLOG_LEVEL["NOTICE"] == "5"
        assert slog.SYSLOG_LEVEL["CRITICAL"] == "2"
        assert slog.SYSLOG_LEVEL["ALERT"] == "1"

    def test_log_level_default(self):
        """Default log level should be DEBUG."""
        assert slog.LOG_LEVEL == slog.SYSLOG_LEVEL["DEBUG"]

    def test_message_no_servers(self):
        """Message should not send when no servers configured."""
        original_servers = slog.SYSLOG_SERVERS
        slog.SYSLOG_SERVERS = []
        mock_socket = MagicMock()
        original_socket = slog.SYSLOG_SOCKET
        slog.SYSLOG_SOCKET = mock_socket
        try:
            slog.message("test message", "INFO")
            mock_socket.sendto.assert_not_called()
        finally:
            slog.SYSLOG_SERVERS = original_servers
            slog.SYSLOG_SOCKET = original_socket

    def test_message_with_server(self):
        """Message should send when servers configured."""
        original_servers = slog.SYSLOG_SERVERS
        slog.SYSLOG_SERVERS = ["192.168.1.1"]
        mock_socket = MagicMock()
        original_socket = slog.SYSLOG_SOCKET
        slog.SYSLOG_SOCKET = mock_socket
        try:
            slog.message("test message", "INFO")
            mock_socket.sendto.assert_called_once()
            call_args = mock_socket.sendto.call_args
            assert b"test message" in call_args[0][0]
            assert call_args[0][1] == ("192.168.1.1", 514)
        finally:
            slog.SYSLOG_SERVERS = original_servers
            slog.SYSLOG_SOCKET = original_socket

    def test_message_multiple_servers(self):
        """Message should send to all configured servers."""
        original_servers = slog.SYSLOG_SERVERS
        slog.SYSLOG_SERVERS = ["192.168.1.1", "10.0.0.1"]
        mock_socket = MagicMock()
        original_socket = slog.SYSLOG_SOCKET
        slog.SYSLOG_SOCKET = mock_socket
        try:
            slog.message("test", "INFO")
            assert mock_socket.sendto.call_count == 2
        finally:
            slog.SYSLOG_SERVERS = original_servers
            slog.SYSLOG_SOCKET = original_socket

    def test_message_socket_error_suppressed(self):
        """Socket errors should be suppressed."""
        original_servers = slog.SYSLOG_SERVERS
        slog.SYSLOG_SERVERS = ["192.168.1.1"]
        mock_socket = MagicMock()
        mock_socket.sendto.side_effect = OSError("test error")
        original_socket = slog.SYSLOG_SOCKET
        slog.SYSLOG_SOCKET = mock_socket
        try:
            # Should not raise
            slog.message("test", "INFO")
        finally:
            slog.SYSLOG_SERVERS = original_servers
            slog.SYSLOG_SOCKET = original_socket
