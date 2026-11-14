# -*- encoding: utf-8

import pytest

from lswifi import completions


class TestCompletions:
    def test_get_completions_empty_args(self):
        """Empty args returns all global options."""
        result = completions.get_completions([], "")
        assert result == completions.global_options()

    def test_uptime_completion_follows_platform(self, monkeypatch):
        monkeypatch.setattr("lswifi.helpers.uptime_available", lambda: False)
        assert "--uptime" not in completions.get_completions([], "")
        assert "--uptime" not in completions.get_completions([], "--up")
        monkeypatch.setattr("lswifi.helpers.uptime_available", lambda: True)
        assert "--uptime" in completions.get_completions([], "")
        assert completions.get_completions([], "--up") == ["--uptime"]

    def test_get_completions_with_prefix(self):
        """Filters options by prefix."""
        result = completions.get_completions([], "--ch")
        assert "--channel-width" in result
        # -channel doesn't match --ch prefix, only --channel-width does
        assert len(result) == 1

    def test_get_completions_channel_width_values(self):
        """After --channel-width, returns width values."""
        result = completions.get_completions(["--channel-width"], "")
        assert result == completions.CHANNEL_WIDTHS

    def test_get_completions_channel_width_with_prefix(self):
        """Filters channel width values by prefix."""
        result = completions.get_completions(["--channel-width"], "1")
        assert "160" in result
        assert "20" not in result

    def test_get_completions_completion_command(self):
        """After 'completion' command, returns shells."""
        result = completions.get_completions(["completion"], "")
        assert result == completions.SHELLS

    def test_get_completions_excludes_used_options(self):
        """Already used options are excluded."""
        result = completions.get_completions(["--debug"], "")
        assert "--debug" not in result
        assert "--version" in result

    def test_rssi_stats_completion(self):
        """--rssi-stats is offered as a completion."""
        result = completions.get_completions([], "--rs")
        assert "--rssi-stats" in result

    def test_filter_completions_no_prefix(self):
        """No prefix returns all options."""
        options = ["--foo", "--bar", "--baz"]
        result = completions._filter_completions(options, "")
        assert result == options

    def test_filter_completions_with_prefix(self):
        """Filters by prefix."""
        options = ["--foo", "--bar", "--baz"]
        result = completions._filter_completions(options, "--b")
        assert result == ["--bar", "--baz"]

    def test_find_command_present(self):
        """Finds completion command when present."""
        result = completions._find_command(["--debug", "completion", "powershell"])
        assert result == "completion"

    def test_find_command_absent(self):
        """Returns None when no command present."""
        result = completions._find_command(["--debug", "--version"])
        assert result is None

    def test_generate_powershell_script(self):
        """Returns non-empty PowerShell script."""
        result = completions.generate_powershell_script()
        assert isinstance(result, str)
        assert "Register-ArgumentCompleter" in result
        assert "lswifi" in result

    def test_generate_bash_script(self):
        """Returns bash script using compgen."""
        result = completions.generate_bash_script()
        assert isinstance(result, str)
        assert "complete -F _lswifi_completion lswifi" in result
        assert "--_complete" in result

    def test_generate_zsh_script(self):
        """Returns zsh script registering compdef."""
        result = completions.generate_zsh_script()
        assert isinstance(result, str)
        assert "#compdef lswifi" in result
        assert "compdef _lswifi lswifi" in result
        assert "compadd" in result

    def test_generate_fish_script(self):
        """Returns fish script registering a completion."""
        result = completions.generate_fish_script()
        assert isinstance(result, str)
        assert "complete -c lswifi" in result
        assert "commandline -opc" in result

    @pytest.mark.parametrize("shell", completions.SHELLS)
    def test_get_completion_script_supported(self, shell):
        """Every advertised shell returns a script."""
        result = completions.get_completion_script(shell)
        assert result is not None
        assert "lswifi" in result

    def test_get_completion_script_unknown(self):
        """Returns None for unknown shell."""
        result = completions.get_completion_script("tcsh")
        assert result is None

    def test_get_completions_option_with_none_value(self):
        """When option maps to None in OPTIONS_WITH_VALUES, return empty list."""
        original = completions.OPTIONS_WITH_VALUES.copy()
        completions.OPTIONS_WITH_VALUES["--test-opt"] = None
        try:
            result = completions.get_completions(["--test-opt"], "")
            assert result == []
        finally:
            completions.OPTIONS_WITH_VALUES.clear()
            completions.OPTIONS_WITH_VALUES.update(original)
