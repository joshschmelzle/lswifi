# -*- coding: utf-8 -*-
#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause

"""
lswifi.completions
~~~~~~~~~~~~~~~~~~

Provides PowerShell tab completion support for lswifi.
"""

from typing import List, Optional

GLOBAL_OPTIONS = [
    "--scans",
    "--interval",
    "--time",
    "-ies",
    "-threshold",
    "-all",
    "-g",
    "-a",
    "-six",
    "-include",
    "-exclude",
    "-bssid",
    "--ap-names",
    "--qbss",
    "--tpc",
    "--period",
    "--uptime",
    "--rnr",
    "--channel-width",
    "-ethers",
    "--append-ethers",
    "--display-ethers",
    "--data-location",
    "-ap",
    "-channel",
    "-raw",
    "--get-interfaces",
    "--list-interfaces",
    "--json",
    "--indent",
    "--csv",
    "-exportraw",
    "-export",
    "-path",
    "-decoderaw",
    "-decode",
    "--bytes",
    "--watchevents",
    "--syslog",
    "--debug",
    "--version",
    "completion",
]

CHANNEL_WIDTHS = ["20", "40", "80", "160", "320"]

SHELLS = ["powershell"]

OPTIONS_WITH_VALUES = {
    "--channel-width": CHANNEL_WIDTHS,
}


def get_completions(args: List[str], current_word: str) -> List[str]:
    """Return context-aware completion suggestions."""
    if not args:
        return _filter_completions(GLOBAL_OPTIONS, current_word)

    last_arg = args[-1] if args else ""

    if last_arg == "--channel-width":
        return _filter_completions(CHANNEL_WIDTHS, current_word)

    if last_arg in OPTIONS_WITH_VALUES and OPTIONS_WITH_VALUES[last_arg] is None:
        return []

    command = _find_command(args)

    if command == "completion":
        return _filter_completions(SHELLS, current_word)

    available_options = [opt for opt in GLOBAL_OPTIONS if opt not in args]
    return _filter_completions(available_options, current_word)


def _filter_completions(options: List[str], prefix: str) -> List[str]:
    """Filter options by prefix."""
    if not prefix:
        return options
    return [opt for opt in options if opt.startswith(prefix)]


def _find_command(args: List[str]) -> Optional[str]:
    """Find the subcommand if present."""
    for arg in args:
        if arg == "completion":
            return arg
    return None


def generate_powershell_script() -> str:
    """Generate the PowerShell tab completion script."""
    return r"""Register-ArgumentCompleter -Native -CommandName lswifi -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandLine = $commandAst.ToString()
    $commandStart = $commandAst.Extent.StartOffset
    $relativePosition = $cursorPosition - $commandStart
    if ($relativePosition -gt $commandLine.Length) {
        $relativePosition = $commandLine.Length
    }
    if ($relativePosition -lt 0) {
        $relativePosition = 0
    }
    $commandText = $commandLine.Substring(0, $relativePosition)

    $words = @()
    $currentWord = $wordToComplete

    if ($commandText -match '^\s*lswifi\s*(.*)$') {
        $afterCmd = $Matches[1]
        $allWords = @($afterCmd -split '\s+' | Where-Object { $_ -ne '' })

        if ($wordToComplete -eq '') {
            $words = $allWords
        } else {
            if ($allWords.Count -gt 1) {
                $words = $allWords[0..($allWords.Count - 2)]
            } else {
                $words = @()
            }
        }
    }

    $argsString = $words -join ' '

    $completionArgs = @('--_complete')
    if ($argsString) {
        $completionArgs += '--_complete_args'
        $completionArgs += $argsString
    }
    $completionArgs += '--_complete_current'
    $completionArgs += $currentWord

    $completions = & lswifi @completionArgs 2>$null

    if ($completions) {
        $completions -split "`n" | ForEach-Object {
            $_.Trim()
        } | Where-Object { $_ -ne '' } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_,
                $_,
                'ParameterValue',
                $_
            )
        }
    }
}
"""


def get_completion_script(shell: str) -> Optional[str]:
    """Get the completion script for the specified shell."""
    if shell == "powershell":
        return generate_powershell_script()
    return None
