![coverage-badge](coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

lswifi: a CLI Wi-Fi scanner tool for Windows
===============================================

Documentation
-------------

`lswifi` is a CLI Wi-Fi scanner tool for Windows that provides more information about nearby Wi-Fi networks than built-in tools. This includes a Received Signal Strength Indicator (RSSI), detection of 802.11 feature set, and more.

Installation
------------

``` {.sourceCode .bash}
> python -m pip install lswifi
```

![alt](/docs/31Pu7mCVFR.gif "animation showing install of lswifi")

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

![alt](/docs/Wtj6xTEisE.gif "animation showing printing verbose information for a particular BSSID")

Print help information:

``` {.sourceCode .bash}
> lswifi -h
```

![alt](/docs/BCKaCek52E.gif "animation showing printing help for lswifi")

Upgrading
---------

Here is how to upgrade `lswifi` when there is a new version available:

```bash
PS C:\Users\josh> pip install --upgrade lswifi
Collecting lswifi
  Using cached lswifi-0.1.1-py2.py3-none-any.whl (57 kB)
Installing collected packages: lswifi
  Attempting uninstall: lswifi
    Found existing installation: lswifi 0.1
    Uninstalling lswifi-0.1:
      Successfully uninstalled lswifi-0.1
Successfully installed lswifi-0.1.1
```

Check the version installed:

```bash
PS C:\Users\josh> lswifi -v
lswifi 0.1.1
```

FAQs
----

1. What OS and Python versions are required to run this?
    - Windows 10 and Python 3.7 are the minimum supported versions.
2. Can you get add information from radio tap headers?
    - Currently there is not a way to get radio tap headers from Native Wifi wlanapi.h.

Contributing
------------

Want to contribute? Thanks! Please take a few moments to [read this](CONTRIBUTING.md).
