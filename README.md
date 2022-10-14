![coverage-badge](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](https://github.com/joshschmelzle/lswifi/blob/main/CODE_OF_CONDUCT.md)

lswifi: a CLI-centric Wi-Fi scanning tool for Windows
===============================================

`lswifi` is a CLI-centric Wi-Fi scanning tool for Windows that provides more information about nearby Wi-Fi networks than built-in tools (e.g. `netsh show wlan networks`). Examples include Received Signal Strength Indicator (RSSI), showing security AKMs and ciphers, parsing 802.11 feature set, and more. With capable Wi-Fi adapters, lswifi can detect and show networks in 2.4 GHz, 5 GHz, and 6 GHz bands.

Installation
------------

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

Output only networks that match `my_ssid`:

``` {.sourceCode .bash}
> lswifi -include my_ssid
```

Output verbose information (including Information Elements) for BSSID `00:00:00:00:00:00`:

``` {.sourceCode .bash}
> lswifi -ies 00:00:00:00:00:00
```

![alt](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/information_elements.gif "animation showing printing verbose information for a particular BSSID")

Print help information:

``` {.sourceCode .bash}
> lswifi -h
```

![alt](https://raw.githubusercontent.com/joshschmelzle/lswifi/main/docs/help_menu.gif "animation showing printing help for lswifi")

CLI options
-----------

```bash
options:
  -h, --help            show this help message and exit
  -version, --version, -V
                        show program's version number and exit
  -n #, --scans #       set how many scans to do before exiting
  --time #              set test in seconds to perform scans for
  -i #, --interval #    seconds between scans
  -ies [BSSID]          print extra information about information elements for a specified BSSID
  -threshold -82, -t -82
                        threshold which excludes networks with weak signal strength from results (-82 is default)
  -g                    display filter to limit output by 2.4 GHz band
  -a                    display filter to limit output by 5 GHz band
  -six                  display filter to limit output by 6 GHz band
  -include SSID         display filter to limit results by specified SSIDs (partial matching supported)
  -exclude SSID         display filter to exclude results by specified SSIDs (partial matching supported)
  -bssid BSSID          display filter to limit results by specified BSSIDs (partial matching supported)
  --ap-names            adds an ap name column to output and will cache ap names locally to help provide consistent results
  --qbss                adds station and utilization columns to output using information from AP beacon QBSS IE
  --tpc                 adds TPC column to output using information from AP beacon 802.11h
  --mfp, --pmf          adds Protected Management Frame column to output using information from AP beacon RSNE
  --period              adds beacon period column to output using information from AP beacon
  --uptime, -uptime     sort output by access point uptime based on beacon timestamp
  --channel-width 20|40|80|160
                        display filter to limit output by a specified channel width
  -ethers               display ap name column and use ethers files for the names
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
  -export [BSSID]       export bss and ies bytefiles. default behavior will export all from a scan. to export only one, provide full mac address of the BSSID as argument.
  -decode BYTEFILE      decode a raw .BSS or .IES file
  --bytes BSSID         output debugging bytes for a specified BSSID found in scan results.
  --watchevents         a special mode which watches for notification on a wireless interface such as connection and roaming events
  --debug               increase verbosity in output for debugging
```

Upgrading
---------

Here is how to upgrade `lswifi` using `pip3` when there is a new version available:

```bash
PS C:\Users\josh> where.exe pip3
C:\Users\josh\AppData\Local\Programs\Python\Python310\Scripts\pip3.exe

PS C:\Users\josh> pip3 install --upgrade lswifi
```

Check the version installed:

```bash
PS C:\Users\josh> lswifi -v
```

FAQs
----

1. What OSes and Python versions are required to run `lswifi`?
    - Windows 10+ and Python 3.7 are the minimum versions I'm willing to support (subject to change).
    - Windows 11 and capable interface required for 6 GHz support.
2. Can you get add information from radio tap headers?
    - Currently there is not a way to get radio tap headers from Native Wifi wlanapi.h.
3. Do I need to install `lswifi` in a virtual environment (venv)?
   - Optional and not necessary. `lswifi` currently has zero third party dependencies.
4. When I run `lswifi` from my Windows terminal I get an error that says `'lswifi' is not recognized as an internal or external command operable program or batch file.`?
   - Make sure the Scripts directory is included in the PATH environment variable and `lswifi.exe` exists in said folder.
   - Here is an example for how to find the Scripts directory:

```bash
C:\Users\josh>python
Python 3.10.4 (tags/v3.10.4:9d38120, Mar 23 2022, 23:13:41) [MSC v.1929 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import os,sys
>>> os.path.join(sys.prefix, 'Scripts')
'C:\\Users\\josh\\AppData\\Local\\Programs\\Python\\Python310\\Scripts'
```

Contributing
------------

Want to contribute? Thanks! Please take a few moments to [read this](https://github.com/joshschmelzle/lswifi/blob/main/CONTRIBUTING.md).
