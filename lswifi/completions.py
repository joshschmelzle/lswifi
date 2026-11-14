#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause

"""
lswifi.completions
~~~~~~~~~~~~~~~~~~

Provides shell tab completion support for lswifi.
"""

from lswifi import helpers

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
    "--rssi-stats",
    "--ap-names",
    "--qbss",
    "--tpc",
    "--period",
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
    "--no-update-check",
    "--debug",
    "--version",
    "completion",
]

CHANNEL_WIDTHS = ["20", "40", "80", "160", "320"]

SHELLS = ["bash", "fish", "powershell", "zsh"]

OPTIONS_WITH_VALUES = {
    "--channel-width": CHANNEL_WIDTHS,
}


def global_options() -> list[str]:
    options = list(GLOBAL_OPTIONS)
    if helpers.uptime_available():
        options.insert(options.index("--period") + 1, "--uptime")
    return options


def get_completions(args: list[str], current_word: str) -> list[str]:
    """Return context-aware completion suggestions."""
    if not args:
        return _filter_completions(global_options(), current_word)

    last_arg = args[-1] if args else ""

    if last_arg == "--channel-width":
        return _filter_completions(CHANNEL_WIDTHS, current_word)

    if last_arg in OPTIONS_WITH_VALUES and OPTIONS_WITH_VALUES[last_arg] is None:
        return []

    command = _find_command(args)

    if command == "completion":
        return _filter_completions(SHELLS, current_word)

    available_options = [opt for opt in global_options() if opt not in args]
    return _filter_completions(available_options, current_word)


def _filter_completions(options: list[str], prefix: str) -> list[str]:
    """Filter options by prefix."""
    if not prefix:
        return options
    return [opt for opt in options if opt.startswith(prefix)]


def _find_command(args: list[str]) -> str | None:
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


def generate_bash_script() -> str:
    """Generate the bash tab completion script."""
    return r"""_lswifi_completion() {
    local cur args i
    cur="${COMP_WORDS[COMP_CWORD]}"
    args=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        args+="${COMP_WORDS[i]} "
    done
    COMPREPLY=($(compgen -W "$(lswifi --_complete --_complete_args "$args" --_complete_current "$cur" 2>/dev/null)" -- "$cur"))
}
complete -F _lswifi_completion lswifi
"""


def generate_zsh_script() -> str:
    """Generate the zsh tab completion script."""
    return r"""#compdef lswifi

_lswifi() {
    local -a args completions
    local i
    for ((i = 2; i < CURRENT; i++)); do
        args+=("${words[i]}")
    done
    completions=(${(f)"$(lswifi --_complete --_complete_args "${(j: :)args}" --_complete_current "${words[CURRENT]}" 2>/dev/null)"})
    if (( ${#completions} )); then
        compadd -a completions
    else
        _default
    fi
}

if [ "$funcstack[1]" = "_lswifi" ]; then
    _lswifi "$@"
else
    compdef _lswifi lswifi
fi
"""


def generate_fish_script() -> str:
    """Generate the fish tab completion script."""
    return r"""function __fish_lswifi_completions
    set -l tokens (commandline -opc)
    set -l current (commandline -ct)
    set -l args (string join ' ' $tokens[2..-1])
    if test (count $args) -eq 0
        set args ''
    end
    lswifi --_complete --_complete_args "$args" --_complete_current "$current" 2>/dev/null
end

complete -c lswifi -f -a '(__fish_lswifi_completions)'
"""


def get_completion_script(shell: str) -> str | None:
    """Get the completion script for the specified shell."""
    if shell == "bash":
        return generate_bash_script()
    if shell == "fish":
        return generate_fish_script()
    if shell == "powershell":
        return generate_powershell_script()
    if shell == "zsh":
        return generate_zsh_script()
    return None
