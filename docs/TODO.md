TODO
====

## IE parsing - For example - Cisco 8821 IE parsing

```
4015 DEB Jul 18 11:22:37.097405 wpa_supplicant(947)-nl80211: Associated on 5240 MHz
4016 DEB Jul 18 11:22:37.097434 wpa_supplicant(947)-nl80211: Associated with 38:17:c3:0a:68:11
4017 DEB Jul 18 11:22:37.097483 wpa_supplicant(947)-nl80211: Operating frequency for the associated BSS from scan results: 5240 MHz
4020 DEB Jul 18 11:22:37.097621 wpa_supplicant(947)-req_ies - hexdump(len=110): 00 07 63 6d 70 2d 76 6f 63 01 08 8c 12 98 24 b0 48 60 6c 21 02 01 0f 24 0a 24 04 34 04 64 0b 95 04 a5 01 30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 00 00 2d 1a 6f 01 17 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7f 03 00 00 08 dd 09 00 10 18 02 00 00 00 00 00 dd 07 00 50 f2 02 00 01 0f
4021 DEB Jul 18 11:22:37.097710 wpa_supplicant(947)-resp_ies - hexdump(len=114): 01 08 8c 12 98 24 b0 48 60 6c 2d 1a ad 09 1b ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3d 16 30 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4a 0e 14 00 0a 00 2c 01 c8 00 14 00 05 00 19 00 7f 08 01 00 08 00 00 00 00 40 dd 18 00 50 f2 02 01 01 84 00 03 a4 00 00 27 a4 00 00 42 43 5e 00 62 32 2f 00
4023 DEB Jul 18 11:22:37.097769 wpa_supplicant(947)-WPA: set own WPA/RSN IE - hexdump(len=22): 30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 00 00
```

## PHX AIRPORT AP NAME CAUSED IN CONSISTENT COLUMN SIZING

```
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

## Implement VHT Tx Power Envelope Parser

TODO

## Make sure memoryview and bytearray is being used for interactions with bytes

https://effectivepython.com/2019/10/22/memoryview-bytearray-zero-copy-interactions

## pwnagotchia

- uses `de:ad:be:ef:de:ad` - could possible decode the data thrown into the IE to
- [ ] determine if it has connected to a pwngrid
- [ ] show stats for when they show up
- [ ] suggest enabling 802.11w
## Exception Handling

- [ ] Review.

## Beacon Size Column

- [ ] May be useful to have a beacon size column

## Hotspot 2.0 detection

- [ ] https://www.wi-fi.org/discover-wi-fi/specifications

## Minmium Requirements

- [X] Python 3.7 and above only at this point.

## Python 3.9

- [X] Test to ese if code works with Python 3.9 (tested January 2021)
## Python 3.8

- [X] Test to see if my code works in Python 3.8 (tested 3.8b1 week 7/1/2019)

## Writing to the screen w/ multiple adapters

- [X] Move the write to screen code out of the `Client` Object. DONE 6/25
- [X] Cache the results. DONE 6/25
- [X] Fire up an event in the client, when the data is stored. After you receive all the events, from all clients/adapters, then you write to screen. DONE 6/25
- [X] Screen output is always the last step and should be isolated from the rest. DONE 6/25
- [ ] Clean up and test all params w/ multiple adapters
- [ ] Write unit tests 

## Notification for duplicate MACs

- [X] Alert users when there are duplicate BSSIDs in the scan results.
- [ ] Write unit test for this to very this is done right.

## sorting, filtering and counters

- [X] Sort output by RSSI
- [ ] Add ability to sort by different columns
- [ ] Options to filter by PHY
- [ ] Write unit tests for these

## Export or silent mode that can be a feed into another program

- [X] --json support has been added
## Verbose

- [ ] Use WlanScan pDot11Ssid to specify a SSID to be scanned. This is for a directed scan on a particular a SSID.
    - [ ] I don't think this is supported by most adapters.
- [ ] Display guard interval in verbose output
- [ ] Move most display items to the verbose output.
- [ ] Move the Security [auth/unicast/group] stuff into verbose.

## Passpoint

- [ ] Add detection for passpoint networks .11u?
- [ ] Add detection for eduroam and openroam networks? (investigate)

## Profiles

- [ ] Default output should be simple and consistent (i.e. displaying QBSS, not all networks have QBSS frame enabled) and display fine on 1080p scaled at 150% screens. 
- [ ] Security should follow None, OWE, WEP, WPA1, WPA2, WPA3, WPA2-Enterprise, WPA3-Enterprise.

## Detecting Windows Terminal vs cmd.exe and features like unicode support

- [ ] Adding lock symbols for example. This may be complex. Doesn't work with cmd.exe. Does it work with Windows Terminal?
- [ ] Investigate if there is any cool stuff we can do with Windows Terminal

## UTF-8

- [ ] Support for UTF-8 encoded SSID names.

## 802.11b

- [ ] HR-DSSS for 5.5 and 11 Mbps, and DSSS for 1 and 2 Mbps - is there a way to display this easily? These both appear to be labeled as ERP on my app.
- [ ] DSSS data encoding uses 22 MHz wide channels. This is because the chips (bits) need 2 MHz of space and there are 11 bits. B only networks should have the channel width listed as 22 MHz.
- [ ] My HR-DSSS test network seems to be classified as ERP. Why?
- [ ] Parse and display the Capabilities based on bit value.

## Export/Import

- [ ] Handle input and decode of WinFi's `.BSS` files - may have to do this manually.
- [X] Add ability to export to .IES and .BSS
- [X] Add ability to decode .IES and .BSS
- [ ] Add ability to export to PCAP.

## Optional/Enhancements

- [ ] Reporting type function or export like function. Splunk?
- [ ] BSSID grouping by AP Base MAC (Cisco:XX:XX:X0-F in 2.4 and XF-0 in 5).
- [ ] Graph view for # of radio on a given channel. Like the MM Dashboard overview on Aruba OS 8.x, but in ASCII!
- [ ] `may have found a way to enable some kind of monitor mode on windows :slightly_smiling_face: including packet injection and stuff` -Helge; WDI (WLAN Device Driver Interface) is the new Universal Windows driver model for Windows 10. WLAN device manufacturers can write a single WDI miniport driver that runs on all device platforms, and requires less code than the previous native WLAN driver model. All new WLAN features introduced in Windows 10 require WDI-based drivers. https://docs.microsoft.com/en-us/windows-hardware/drivers/network/wifi-universal-driver-model 
- [ ] Explore use of WDI (WLAN Device Driver Interface) filter drivers - for certain Radio Tap Headers.

## Current connection

- [X] Add flag that only displays current connection info to screen (like `airport -i` on macOS)

## Unit Testing (pytest)

- UNIT TESTING SHOULD BE DONE WITH PYTEST
- [ ] Add unit tests - would be useful to have a load function to do this with - something that i can tell users to export if they have issues, then i can fix in the app - i really need to fucking do this.
    - [ ] test with WPA3
    - [ ] test with Enhanced Open/OWE
    - [ ] test for SS support
    - [ ] test with 11ax (HE), 11ac (VHT), 11n (HT), 11g (ERP), 11b (HR-DSSS vs DSSS), 11a (OFDM)
    - [ ] test 5 ghz with 20, 40, 80, 160 mhz networks
    - [ ] test 2.4 ghz networks with 20 and 40 mhz networks
    - [ ] Add ability to export .BSS
    - [ ] Add ability to export .IES
- [ ] Export BSS and IES feature from all detected devices. A record sort of function.
- [ ] Export BSS and IES feature for a specific BSSID. A record sort of function.

## other types of networks

- [ ] WiDi/Miracast/WiFi Direct Networks.
- [ ] WPS is IE 221, OUI 00-50-F2 (Microsoft), and Type 4 --- there is device name in this field.

## improvements involving spatial streams

- [ ] investigate WDI_TLV_INTERFACE_CAPABILITIES usage for supported Rx and Tx spatial streams for a particular interface. 
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/network/wdi-tlv-interface-capabilities#requirements
    - UNIT8 	The supported number of RX spatial streams.
    - UNIT8     The supported number of TX spatial streams.

## information elements 

- [ ] Calculate min and max rates
- [ ] Parse HT Operation
- [ ] Parse HT Capabilities
    - [X] Show # of spatial streams as a column. (DONE 2019-01-28)
    - [ ] Show # of spatial streams under VHT elments
- [ ] If column has nothing to display. Don't display the column?
- [ ] Make IE's objects associated with main class.
- [ ] Display QBSS Load in Scan Results
    - utilization (add sort by option?)
    - station count (add sort by option?)
- [ ] Parse HT Capabilities
- [ ] AKM ID for WPA3
- [ ] AKM ID for Enhanced Open
    - [x] We know it's ID 18 based on decoded Aruba AP IE and Prague '18 slides.
    - [ ] Should we call it Enhanced Open or OWE? I think OWE. Think about this. Technical vs WFA name.
- [ ] Add WPA, WPA2, WPA/WPA2 WPA2-Enterprise, WPA3, WPA3-Enterprise, Open, WEP, OWE, OWE Transition highlights for security
- [ ] Refactor RSN element and catch KeyErrors whenever doing DICT lookups so that prog doesn't crash.
- [ ] WEP is showing up with `None` security. This is because a WEP network does not appear to have a RSNE element. Expected. How do we detect WEP? 
- [ ] Parse WMM element (microsoft vendor specific).
- [ ] Add support for 160 MHz channels (get an AP that does 160 MHz wide channels)
    - [ ] Split channels out meaning identify primary and secondary channels in output.
        - [ ] 20 (20 MHz)
        - [ ] 20+20 (40 MHz)
        - [ ] 40+40 (80 MHz)
        - [ ] 80+80 (160 MHz)
- [ ] AP names
    - [ ] Cisco Aironet IE
    - [ ] Cisco Meraki
        - is this available?
    - [X] Aruba
    - [ ] Aerohive (IE 221, OUI 00:19:77, Subtype: 33) Aerohive is now owned by Extreme
    - [ ] Mist
    - [ ] Extreme IdentiFi
    - [ ] Extreme WiNG
    - ~~[ ] Ruckus~~
        - early 2019 this was not a thing.
- [ ] Split out both PHY types into supported modes when network supports both N, AC
    - [ ] a/n/ac/ax
    - [ ] b/g/n/ax
- [ ] Record function that can be imported into Helge's program with the WinFi Scan File.
- [ ] Record function for a directed scan - reverse engineer Helge's BSS / IES files. 
    - [X] IES is done
    - [ ] BSS - not sure how to do this?

## documentation

- [ ] Add contribution guidelines and what we need from users to help troubleshoot when there is an issue.
    - Like export of the IES and BSS so that I can analyze them. Or export of the PCAP?
    - Logs? Watchevents? Debug?
- [ ] Review class design and organizing code.

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
        + https://en.wikipedia.org/wiki/IEEE_802.11i-2004
    - [X] 802.11d support info -> IE 7 -> Country Element 
        + 802.11d-2001 is the 802.11 amendment that provides regulatory domain information. When it's enabled, a Country Information elmeent is added to the beacons/probe responses.
    - [X] 802.11e support info -> IE 11 -> QBSS Load
    - [X] 802.11h support info -> IE 33 -> Power Capability
        + Association/Reassociation frames - probably not beacon/probe... may not be able to retrieve
    - [X] 802.11h support info -> IE 36 -> Supported Channels 
        + Association/Reassociation frames - probably not beacon/probe... may not be able to retrieve        
    - [X] 802.11h support info -> IE 32 -> Power Constraint element
        + When 802.11h Power Constraint is enabled it will transmit IE 32 in beacon/probe frames.
        + 802.11h operations consist of 2 mechanism - (Dynamic Freq Selection) DFS and (Transmit Power Control) TPC
    - [X] 802.11s mesh configuration -> IE 113
    - [X] 802.11w protection - IE 48 (parsing RSN Capabilities sub field) 
- [X] Add support for registering and unregistering from notifications from wireless interfaces. DONE March/April 2019
- [X] Add AP uptime column via BEACON timestamp. DONE 2019/04/16
- [X] On the counter that is displayed `225 BSSIDs detected; displaying info for 225 BSSIDs at -82 sensitivity` make this updated based on what's in the out list.
    + Currently this number is wrong. FIXED 20190411
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
