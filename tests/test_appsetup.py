# -*- encoding: utf-8

import argparse

import pytest

from lswifi import appsetup


class TestSensitivity:
    def test_valid_sensitivity(self):
        """Valid sensitivity values should pass."""
        assert appsetup.sensitivity("-82") == -82
        assert appsetup.sensitivity("-1") == -1
        assert appsetup.sensitivity("-110") == -110

    def test_invalid_sensitivity_out_of_range(self):
        """Values outside -110 to -1 should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.sensitivity("0")
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.sensitivity("-111")

    def test_invalid_sensitivity_not_integer(self):
        """Non-integer values should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.sensitivity("abc")


class TestJsonIndent:
    def test_valid_indent(self):
        """Valid indent values 0-4 should pass."""
        assert appsetup.json_indent("0") == 0
        assert appsetup.json_indent("2") == 2
        assert appsetup.json_indent("4") == 4

    def test_none_indent(self):
        """None should return None."""
        assert appsetup.json_indent(None) is None

    def test_invalid_indent_out_of_range(self):
        """Values >= 5 should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.json_indent("5")

    def test_invalid_indent_not_integer(self):
        """Non-integer values should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.json_indent("abc")


class TestWidth:
    def test_valid_widths(self):
        """Valid channel widths should pass."""
        assert appsetup.width("20") == "20"
        assert appsetup.width("40") == "40"
        assert appsetup.width("80") == "80"
        assert appsetup.width("160") == "160"
        assert appsetup.width("320") == "320"

    def test_none_width(self):
        """'None' string should return None."""
        assert appsetup.width("None") is None

    def test_invalid_width(self):
        """Invalid widths should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.width("50")


class TestSyslogIp:
    def test_valid_single_ip(self):
        """Valid single IP should pass."""
        result = appsetup.syslog_ip("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_valid_multiple_ips(self):
        """Valid comma-separated IPs should pass."""
        result = appsetup.syslog_ip("192.168.1.1,10.0.0.1")
        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_none_ip(self):
        """'None' string should return None."""
        assert appsetup.syslog_ip("None") is None

    def test_invalid_ip(self):
        """Invalid IP should raise error."""
        with pytest.raises(argparse.ArgumentTypeError):
            appsetup.syslog_ip("not.an.ip.address")


class TestParseCompletionArgs:
    def test_no_complete_flag(self):
        """Returns None when --_complete not present."""
        result = appsetup.parse_completion_args(["--debug"])
        assert result is None

    def test_complete_with_args_and_current(self):
        """Parses args and current word correctly."""
        argv = ["--_complete", "--_complete_args", "--debug", "--_complete_current", "--v"]
        result = appsetup.parse_completion_args(argv)
        assert result == ("--debug", "--v")

    def test_complete_empty_values(self):
        """Returns empty strings when values not provided."""
        argv = ["--_complete"]
        result = appsetup.parse_completion_args(argv)
        assert result == ("", "")
