![pypi-badge](https://img.shields.io/pypi/v/lswifi) ![pypi-format](https://img.shields.io/pypi/format/lswifi) ![pypi-implementation](https://img.shields.io/pypi/implementation/lswifi) ![pypi-version](https://img.shields.io/pypi/pyversions/lswifi) ![coverage-badge](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](https://github.com/joshschmelzle/lswifi/blob/main/CODE_OF_CONDUCT.md)

<img src="https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/lswifi_orange_crop.png" width="400">

`lswifi` is a CLI-centric Wi-Fi scanning tool for Windows that provides more information about nearby Wi-Fi networks than built-in tools (e.g. `netsh wlan show networks`). Examples include Received Signal Strength Indicator (RSSI), showing security AKMs and ciphers, decoding 802.11 IEs, revealing 6 GHz Reduced Neighbor Reports, and more. With capable Wi-Fi adapters, lswifi can detect and show networks in 2.4 GHz, 5 GHz, and 6 GHz bands.

Note: Recent versions of Windows add OFDM rates, RSSI, AKMs and ciphers, QBSS, and limited RNR information to `netsh wlan` output. `lswifi` still offers additional information, parsing, filtering, and output options.

Installation
------------

Note: The Python Scripts directory must be added to the PATH environment variable.

``` {.sourceCode .bash}
> python -m pip install lswifi
```

![alt](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/pip_install.gif "animation showing install of lswifi")

Usage
-----

Output nearby Wi-Fi networks:

``` {.sourceCode .bash}
> lswifi
```

Output nearby Wi-Fi networks that have a detected signal of `-60 dBm` or stronger:

``` {.sourceCode .bash}
> lswifi -t -60
```

Output only networks that match `SegaGenesis` (partial match support):

``` {.sourceCode .bash}
> lswifi -include SegaGenesis
```

Output verbose information (including Information Elements) for BSSID `00:00:00:00:00:00` (exact match):

``` {.sourceCode .bash}
> lswifi -ies 00:00:00:00:00:00
```

![alt](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/information_elements.gif "animation showing printing verbose information for a particular BSSID")

Print help information:

``` {.sourceCode .bash}
> lswifi -h
```

![alt](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/help_menu.gif "animation showing printing help for lswifi")

Print and add detected AP names column in output:

``` {.sourceCode .bash}
> lswifi --ap-names
```

Print and add detected AP names and QBSS column in output (try adding --mfp or --tpc too!):

``` {.sourceCode .bash}
> lswifi --ap-names --qbss
```

Print an alternative table for BSSes which may contain 6 GHz Reduced Neighbor Reports:

``` {.sourceCode .bash}
> lswifi -rnr
```

Watch event notifications (inc. roaming, connection, scanning, etc.):

``` {.sourceCode .bash}
> lswifi --watchevents
```

Export scan results to pcap:

``` {.sourceCode .bash}
> lswifi -export
```

PowerShell Tab Completion
-------------------------

To enable PowerShell tab completion for `lswifi`, run the following command in PowerShell:

``` {.sourceCode .powershell}
lswifi completion powershell | Out-String | Invoke-Expression
```

To make this permanent, add the above command to your PowerShell profile. To find and edit your profile:

``` {.sourceCode .powershell}
# View your profile location
$PROFILE

# Add the completion script to your profile
lswifi completion powershell | Out-String | Invoke-Expression >> $PROFILE

# Or edit manually
notepad $PROFILE
```

Then restart PowerShell or reload your profile:

``` {.sourceCode .powershell}
. $PROFILE
```

CLI options
-----------

```ascii
positional arguments:
  {completion}          commands
    completion          Generate shell completion script

CLI options
-----------

```ascii
positional arguments:
  {completion}          commands
    completion          Generate shell completion script

options:
  -h, --help            show this help message and exit
  -version, --version, -V
                        show program's version number and exit
  -n, --scans #         set how many scans to do before exiting
  --time #              set test in seconds to perform scans for
  -i, --interval #      seconds between scans
  -ies [BSSID]          print extra information about information elements for a specified BSSID
  -threshold, -t -82    threshold which excludes networks with weak signal strength from results (-82 is default)
  -all                  remove threshold filtering which excludes results with weaker signal
  -g                    display filter to limit output by 2.4 GHz band
  -a                    display filter to limit output by 5 GHz band
  -six                  display filter to limit output by 6 GHz band
  -include, -inc SSID   display filter to limit results by specified SSIDs (partial matching supported)
  -exclude, -exc SSID   display filter to exclude results by specified SSIDs (partial matching supported)
  -bssid, -bss BSSID    display filter to limit results by specified BSSIDs (partial matching supported)
  --ap-names            adds an ap name column to output and will cache ap names locally to help provide consistent results
  --qbss                adds station and utilization columns to output using information from AP beacon QBSS IE
  --tpc                 adds TPC column to output using information from AP beacon 802.11h
  --period              adds beacon period column to output using information from AP beacon
  --uptime, -uptime     sort output by access point uptime based on beacon timestamp
  -rnr, --rnr           special mode to create an alternate table based on RNR results
  --channel-width 20|40|80|160|320
                        display filter to limit output by a specified channel width
  -ethers               adds an ap name column to output and use an ethers file for the ap names
  --append-ethers BSSID,APNAME
                        append BSSID and AP name to ethers file for AP names
  --display-ethers      display the list of saved ethers; (BSSID,APNAME) mapping
  --data-location       displays where config items are stored on the local machine
  -ap                   print the BSSID of the connected AP
  -channel              print the channel of the connected AP
  -raw                  format output as the raw value for other scripts (for -ap and -channel only)
  --get-interfaces      print current Wi-Fi status and information
  --list-interfaces     print a list of available WLAN interfaces
  --json [JSON]         output will be formatted as json
  --indent 4            JSON output will be formatted with pretty print with provided indent level
  --csv [CSV]           output will be formatted as csv
  -exportraw, -expraw [BSSID]
                        export raw bss and ies bytefiles. default behavior will export all from a scan. to export only one, provide full mac address of the BSSID as argument.
  -export, -exp [BSSID]
                        export scan results to pcapng file. default behavior will export all from a scan. to export only one, provide full mac address of the BSSID as argument.
  -path EXPORT_PATH     specify output path for pcapng export (defaults to app data directory)
  -decoderaw BYTE_FILE  decode a raw .BSS or .IES file
  -decode PCAP_FILE     parse scan results from pcap/pcapng file. by default shows all networks in the file, can be combined with filtering options.
  --bytes BSSID         output debugging bytes for a specified BSSID found in scan results.
  --watchevents         a special mode which watches for notification on a wireless interface such as connection and roaming events
  --syslog <server IP>  syslogs events from --watchevents to a remote syslog server
  --debug               increase verbosity for debugging
```
