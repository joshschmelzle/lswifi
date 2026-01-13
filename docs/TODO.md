# TODO

A collection of TODOs.

## Handle non-printable characters better

This is applicable when non-printable characters are in the SSID column, or perhaps the AP NAME column when `--ap-names` is used:

```text
-+~~+~+=~+=+++==+=+-  -+~+=~+=~+++=~~~~+=-  -~~~~~~+==~=~+-  -~+~-  -+-  -=+~~+-  --  -=~~==~+=~~=-  -=~++~=+~~=+-
               ESSID  BSSID                 AP NAME          RSSI   .11  CHANNEL  SS  AMENDMENTS     AP UPTIME
      [Network Name]  (*): connected                         [dBm]       [#@MHz]      [802.11]       [approx.]
-+==~=+=~+==~~=~==+-  -=~====+=+~~~+===~+-  -~====++++=~~=-  -==~-  -+-  -+=++~-  --  -++~+~+~~~~~-  -+==+~~+=~==-
    Passpoint Secure  00:fe:c8:ab:cb:0d     PHX-T4-C3-M10B  -50    ac    52@40+  3   d/e/h/i/k/u/v  14d 17:14:05
Free PHX Boingo WiFi  00:fe:c8:ab:cb:0f     PHX-T4-C3-M10B  -52    ac    52@40+  3   d/e            14d 17:14:05
      Boingo Hotspot  00:fe:c8:ab:cb:0e     PHX-T4-C3-M10B  -52    ac    52@40+  3   d/e            14d 17:14:05
   WIVU-0026B88486D1  00:26:b8:84:86:d1                      -54    n    161@40-  2   d/e            02d 18:43:22
Free PHX Boingo WiFi  f4:0f:1b:ac:d4:ff     PHX-T4-C3-M10  -54    ac   100@40+  3   d/e            36d 15:40:51
      Boingo Hotspot  f4:0f:1b:ac:d4:fe     PHX-T4-C3-M10  -55    ac   100@40+  3   d/e            36d 15:40:51
        MWTV3-0105d4  0c:61:27:01:05:d4     MWTV3dev         -55    ac    40@20   2   e/i            00d 1:47:18
    Passpoint Secure  f4:0f:1b:ac:d4:fd     PHX-T4-C3-M10  -55    ac   100@40+  3   d/e/h/i/k/u/v  36d 15:40:51
  WillHackForWaffles  d6:53:83:a9:d8:e5(*)                   -56    n      1@20   2   d/e/h/i/v      00d 0:10:15
      Boingo Hotspot  00:fe:c8:bd:79:ce     PHX-T4-C3-M08B  -57    ac   112@40-  3   d/e            42d 8:00:29
   WIVU-109FA9067228  10:9f:a9:06:72:28                      -57    n    161@40-  2   d/e            02d 18:43:11
Free PHX Boingo WiFi  00:fe:c8:ab:cb:00     PHX-T4-C3-M10B  -58    n      1@20   3   d/e            38d 18:37:24
      Boingo Hotspot  f4:0f:1b:ac:d4:f1     PHX-T4-C3-M10  -58    n      1@20   3   d/e            36d 15:40:56
    Passpoint Secure  00:fe:c8:bd:79:cd     PHX-T4-C3-M08B  -58    ac   112@40-  3   d/e/h/i/k/u/v  42d 8:00:29
Free PHX Boingo WiFi  f4:0f:1b:ac:d4:f0     PHX-T4-C3-M10  -58    n      1@20   3   d/e            36d 15:40:56
      Boingo Hotspot  00:fe:c8:ab:cb:01     PHX-T4-C3-M10B  -58    n      1@20   3   d/e            38d 18:37:35
Free PHX Boingo WiFi  00:fe:c8:bd:79:cf     PHX-T4-C3-M08B  -59    ac   112@40-  3   d/e            42d 8:00:29
      Boingo Hotspot  c4:f7:d5:ea:a7:ce     PHX-T4-C3-M11  -60    ac    52@40+  3   d/e            103d 12:34:47
Free PHX Boingo WiFi  c4:f7:d5:ea:a7:cf     PHX-T4-C3-M11  -60    ac    52@40+  3   d/e            103d 12:34:47
    Passpoint Secure  c4:f7:d5:ea:a7:cd     PHX-T4-C3-M11  -60    ac    52@40+  3   d/e/h/i/k/u/v  103d 12:34:47
    Passpoint Secure  f4:0f:1b:b5:21:bd     PHX-T4-C3-M09  -63    ac    52@40+  3   d/e/h/i/k/u/v  58d 19:54:45
      Boingo Hotspot  f4:0f:1b:b5:21:be     PHX-T4-C3-M09  -63    ac    52@40+  3   d/e            58d 19:54:45
     CenturyLink2678  9c:97:26:5b:90:63                      -68    n     11@20   2   e/i            252d 21:12:48
         iStore Demo  e2:55:6d:8a:0e:91       -68    ac    44@80   2   d/e/h/i/v      01d 0:37:02
Free PHX Boingo WiFi  f4:0f:1b:b5:21:bf     PHX-T4-C3-M09  -69    ac    52@40+  3   d/e            58d 19:54:38
Free PHX Boingo WiFi  c4:f7:d5:ea:a8:6f     PHX-T4-C3-M12  -71    ac   100@40+  3   d/e            79d 14:59:42
    Passpoint Secure  c4:f7:d5:ea:a8:6d     PHX-T4-C3-M12  -71    ac   100@40+  3   d/e/h/i/k/u/v  79d 14:59:42
      Boingo Hotspot  00:fe:c8:87:9c:ee     PHX-T4-C3-M11B  -71    ac   112@40-  3   d/e            49d 1:24:29
      Boingo Hotspot  c4:f7:d5:ea:a8:6e     PHX-T4-C3-M12  -71    ac   100@40+  3   d/e            79d 14:59:42
Free PHX Boingo WiFi  f4:0f:1b:c1:07:8f     PHX-T4-C3-M08  -72    ac   132@40+  3   d/e/v          14d 17:09:51
      Boingo Hotspot  f4:0f:1b:c1:07:8e     PHX-T4-C3-M08  -72    ac   132@40+  3   d/e/v          14d 17:09:51
    Passpoint Secure  f4:0f:1b:c1:07:8d     PHX-T4-C3-M08  -72    ac   132@40+  3   d/e/i/u/v      14d 17:09:51
      Boingo Hotspot  c4:f7:d5:ea:a7:c1     PHX-T4-C3-M11  -75    n      1@20   3   d/e            17d 11:30:41
         iStore Demo  e2:55:7d:8a:0e:91       -75    n      1@20   2   d/e/h/i/v      01d 1:42:20
Free PHX Boingo WiFi  00:fe:c8:87:9c:ef     PHX-T4-C3-M11B  -78    ac   112@40-  3   d/e            49d 1:24:40
    Passpoint Secure  00:fe:c8:87:9c:ed     PHX-T4-C3-M11B  -79    ac   112@40-  3   d/e/h/i/k/u/v  49d 1:24:40
      Boingo Hotspot  00:fe:c8:bd:79:c1     PHX-T4-C3-M08B  -80    n      6@20   3   d/e            42d 8:00:37
Free PHX Boingo WiFi  c4:f7:d5:ea:b0:5f     PHX-T4-C2-T05  -81    ac   140@40+  3   d/e            27d 20:01:51
```

## Implement ~~VHT~~ Tx Power Envelope Parser

This element is not specific to VHT. It is also found in HE in 6 GHz.

- [X] Added in 85517b8461c32704e925b020d7c2878228dd3cad

## Leverage memoryview for interactions with bytes

Use memoryview slicing instead of bytes slicing. This should speed up the profiling of IEs. Move this into a design document?

<https://effectivepython.com/2019/10/22/memoryview-bytearray-zero-copy-interactions>

## pwnagotchia

Consider trying to add support for detecting pwnagotchias nearby.

- uses `de:ad:be:ef:de:ad` - could possible decode the data thrown into the IE to
- [ ] determine if it has connected to a pwngrid
- [ ] show stats for when they show up
- [ ] could suggest enabling 802.11w

## Passpoint and Hotspot 2.0 detection

- [ ] Add detection for Passpoint networks (.11u)?
- [ ] <https://www.wi-fi.org/discover-wi-fi/specifications>

## Minimum Requirements and Tested Versions

- [X] Python 3.7 and above only at this point.

Tested versions:

- [X] Python 3.7.x  
- [X] Python 3.8 (tested 3.8b1 week 7/1/2019)
- [X] Python 3.9 (tested January 2021)
- [X] Python 3.10rc2 (tested September 2021)

## Writing to the screen w/ multiple adapters

- [X] Move the write to screen code out of the `Client` Object. DONE 6/25
- [X] Cache the results. DONE 6/25
- [X] Fire up an event in the client, when the data is stored. After you receive all the events, from all clients/adapters, then you write to screen. DONE 6/25
- [X] Screen output is always the last step and should be isolated from the rest. DONE 6/25
- [ ] Clean up and test all params w/ multiple adapters
- [ ] Write unit tests

## Notification for duplicate MACs

- [X] Alert users when there are duplicate BSSIDs in the scan results.
- [ ] Write unit test for this to verify this is done right.

## sorting, filtering and counters

- [X] Sort output by RSSI
- [ ] Add ability to sort by different columns?
- [X] Options to filter by PHY. We're now able to sort by 5 GHz with `-a`, 2.4 GHz with `-g`, and 6 GHz with `-six`.
- [ ] Write unit tests for these

## Export or silent mode that can be a feed into another program

- [X] `--json` support has been added

## Detecting Windows Terminal vs cmd.exe and features like unicode support

This may be dependent on what shell on Windows is used. Windows Terminal versus Command Prompt for example.

- [ ] Adding lock symbols for example. This may be complex. Doesn't work with cmd.exe. Does it work with Windows Terminal?
- [ ] Investigate if there is any cool stuff we can do with Windows Terminal
- [ ] Support for UTF-8 encoded SSID names.

## 802.11b

- [ ] HR-DSSS for 5.5 and 11 Mbps, and DSSS for 1 and 2 Mbps - is there a way to display this easily? These both appear to be labeled as ERP on my app.
- [ ] DSSS data encoding uses 22 MHz wide channels. This is because the chips (bits) need 2 MHz of space and there are 11 bits. 802.11b only networks should have the channel width listed as 22 MHz.
- [ ] My HR-DSSS test network seems to be classified as ERP. Why?
- [ ] Parse and display the Capabilities based on bit value.

## Export/Import

- [ ] Handle input and decode of WinFi's `.BSS` files - may have to do this manually.
- [X] Add ability to import / export to .IES and .BSS
- [X] Add ability to import / export .IES and .BSS together into a single file for 1 network or multiple networks.
- [ ] Add ability to export to PCAP.

## Optional/Enhancements

- [ ] Reporting type function or export like function. Splunk?
- [X] BSSID grouping by AP Base MAC (Cisco:XX:XX:X0-F in 2.4 and XF-0 in 5). Partial matching with `-bssid` include filter works today.

## Current connection

- [X] Add flag that only displays current connection info to screen (like `airport -i` on macOS)

## Unit Testing (pytest)

All unit testing should be done with pytest.

First step to capabilities testing is to have some sort of record function for a set of results which can be exported and then imported for testing.

## Detection for other types of networks

- [ ] WiDi/Miracast/WiFi Direct Networks.
- [X] WPS is IE 221, OUI 00-50-F2 (Microsoft), and Type 4 --- there is device name in this field.

## Potential Improvements for Spatial Stream detection

- [ ] investigate WDI_TLV_INTERFACE_CAPABILITIES usage for supported Rx and Tx spatial streams for a particular interface.
  - <https://docs.microsoft.com/en-us/windows-hardware/drivers/network/wdi-tlv-interface-capabilities#requirements>
  - UNIT8 - The supported number of RX spatial streams.
  - UNIT8 - The supported number of TX spatial streams.

## Information Elements

- [ ] Calculate min and max rates
- [X] Parse HT Operation
- [X] Show # of spatial streams as a column. (DONE 2019-01-28)
- [X] Parse HT Capabilities
- [ ] Refactor RSN element and catch KeyErrors whenever doing DICT lookups so that prog doesn't crash.
- [X] WEP is showing up with `None` security. This is because a WEP network does not appear to have a RSNE element. Expected. How do we detect WEP? We detect WEP when there is a lack of RSN and the capabilities information privacy bit is set to 1.
- [X] Parse WMM element (microsoft vendor specific).
- [X] Add support for 160 MHz channels (get an AP that does 160 MHz wide channels). This should work for 5 GHz and 6 GHz now.

## AP names

Nick has some information on this blog about this <https://www.nickjvturner.com/ap-name-broadcast-support>.

- [X] Cisco Aironet IE
- [X] Cisco Meraki
- [X] Aruba
- [X] Aerohive (IE 221, OUI 00:19:77, Subtype: 33) Aerohive is now owned by Extreme
- [X] Mist
- [ ] Extreme IdentiFi?
- [X] Extreme WiNG
- [X] Commscope Ruckus (does Ruckus have option to include AP names in their beacons?)

DONE
====

- [X] Logging using the logging module. DONE: 20190912
- [X] Would like to remove dependency on comtypes for GUID if possible. Clean code. DONE: 20190912
- [X] Get the BSSID of the AP that I'm currently connected to.
  - > lswifi --ap
  - > (interface) Access Point: (BSSID)
  - > lswifi --ap --raw
  - > (BSSID)
- [X] Add column for amendments info
  - [X] 802.11k support info -> IE 70 -> RM Enabled Capabilities
  - [X] 802.11r support info -> IE 54 -> BSS Transition
  - [X] 802.11v support info -> IE 127 -> Inside the Extended capabilities
  - [X] 802.11i support info -> IE 48 -> RSNE
    - <https://en.wikipedia.org/wiki/IEEE_802.11i-2004>
  - [X] 802.11d support info -> IE 7 -> Country Element
    - 802.11d-2001 is the 802.11 amendment that provides regulatory domain information. When it's enabled, a Country Information elmeent is added to the beacons/probe responses.
  - [X] 802.11e support info -> IE 11 -> QBSS Load
  - [X] 802.11h support info -> IE 33 -> Power Capability
    - Association/Reassociation frames - probably not beacon/probe... may not be able to retrieve
  - [X] 802.11h support info -> IE 36 -> Supported Channels
    - Association/Reassociation frames - probably not beacon/probe... may not be able to retrieve
  - [X] 802.11h support info -> IE 32 -> Power Constraint element
    - When 802.11h Power Constraint is enabled it will transmit IE 32 in beacon/probe frames.
    - 802.11h operations consist of 2 mechanism - (Dynamic Freq Selection) DFS and (Transmit Power Control) TPC
  - [X] 802.11s mesh configuration -> IE 113
  - [X] 802.11w protection - IE 48 (parsing RSN Capabilities sub field)
- [X] Add support for registering and unregistering from notifications from wireless interfaces. DONE March/April 2019
- [X] Add AP uptime column via BEACON timestamp. DONE 2019/04/16
- [X] On the counter that is displayed `225 BSSIDs detected; displaying info for 225 BSSIDs at -82 sensitivity` make this updated based on what's in the out list.
  - Currently this number is wrong. FIXED 20190411
- [X] Allow SSID filtering to match on partial. e.g., `lswifi -s wifi` would include `xfinitywifi` in the results. (DONE ???)
- [X] Handle various mac address formats - like if 00-00-00-00-00-00 is used as input, automatically convert it. (DONE 2019-01-29)
- [X] (DONE circa 1/26-1/28) - Add Generations 1, 2, 3 in addt. to 4, 5, 6 (even though the WFA alliance only specifies 4, 5, 6. Perhaps look up Keith Parson's Tweet on this.)
- [X] `Advanced Details` instead of `Additional Details` for verbose similar to WiFi Explorer Pro (DONE 2018-01-27)
- [X] Handle input and decode of Helge's IES (DONE 2019-01-27)
- [X] Add flag for 2.4 GHz only - this is for filtering (DONE 2019-01-26)
- [X] Add flag for 5.0 GHz only - this is for filtering (DONE 2019-01-26)
- [X] Display filter by OUI (DONE 2019-01-26)
- [X] Fix `ValueError: 5023 is not a valid SystemErrorCodes` this seems to happen when the adapter is not connected. Ths Wi-Fi interface is on. (2019-01-25)
- [X] Fix `Exception: wlan_scan failed: SystemErrorCodes.ERROR_NDIS_DOT11_POWER_STATE_INVALID:2150899714` this seems to happen when the Wi-Fi interface is turned off. (2019-01-25)
- [x] Highlight currently connected BSSID (DONE 2019-01-24)
