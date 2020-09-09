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

Output only networks that match `myssid`:

``` {.sourceCode .bash}
> lswifi -include myssid
```

Output verbose information (including Information Elements) for BSSID `00:00:00:00:00:00`:

``` {.sourceCode .bash}
> lswifi -ies 00:00:00:00:00:00
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
