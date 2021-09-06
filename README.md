![coverage-badge](https://github.com/joshschmelzle/lswifi/blob/main/coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](https://github.com/joshschmelzle/lswifi/blob/main/CODE_OF_CONDUCT.md)

lswifi: a CLI-centric Wi-Fi scanner tool for Windows
===============================================

Documentation
-------------

`lswifi` is a CLI-centric Wi-Fi scanner tool for Windows that provides more information about nearby Wi-Fi networks than built-in tools. This includes a Received Signal Strength Indicator (RSSI), detection of 802.11 feature set, and more.

Installation
------------

``` {.sourceCode .bash}
> python -m pip install lswifi
```

![alt](https://github.com/joshschmelzle/lswifi/blob/main/docs/31Pu7mCVFR.gif "animation showing install of lswifi")

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

![alt](https://github.com/joshschmelzle/lswifi/blob/main/docs/Wtj6xTEisE.gif "animation showing printing verbose information for a particular BSSID")

Print help information:

``` {.sourceCode .bash}
> lswifi -h
```

![alt](https://github.com/joshschmelzle/lswifi/blob/main/docs/BCKaCek52E.gif "animation showing printing help for lswifi")

Upgrading
---------

Here is how to upgrade `lswifi` when there is a new version available:

```bash
PS C:\Users\josh\GitHub\lswifi> where.exe pip3
C:\Users\josh\AppData\Local\Programs\Python\Python39\Scripts\pip3.exe

PS C:\Users\josh\GitHub\lswifi> pip3 install --upgrade lswifi
```

Check the version installed:

```bash
PS C:\Users\josh> lswifi -v
```

FAQs
----

1. What OS and Python versions are required to run this?
    - Windows 10 and Python 3.7 are the minimum supported versions.
2. Can you get add information from radio tap headers?
    - Currently there is not a way to get radio tap headers from Native Wifi wlanapi.h.

Contributing
------------

Want to contribute? Thanks! Please take a few moments to [read this](https://github.com/joshschmelzle/lswifi/blob/main/CONTRIBUTING.md).
