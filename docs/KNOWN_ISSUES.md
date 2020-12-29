KNOWN ISSUES
============

# NIC removed after scan requested, but before scan complete returns System Error Code 1168

System Error Code 1168 is thrown if an interface is removed between scan_requested and scan_complete events.  

The following message is displayed on the screen.

`wlan_scan failed: SystemErrorCodes.ERROR_NOT_FOUND:1168`

One way to reproduce is to use a USB WLAN NIC. Yank the NIC immediately after initiating a scan.

# Intel 7260 does not report correct WLAN_RATE_SET rates. 

Discovered on 2019/07/01. Comparing Supported Rates IE vs WLAN_RATE_SET using the same specs leads to different data.

Compare the two columns:

```
-~~=~~==+==+=~=+====++~==-  -+~++~=+==~~==~~+~~==+~++=+~+=+=++=+~+~+=+~++=+-
     SUPPORTED RATES                         WLAN_RATE_SET
  (*): basic rate [Mbps]                 (*): basic rate [Mbps]
-~~=+====~~~=~~+==~~~=~+~-  -~=~=+==+===~~~~++~=++=~~==~=+++~+=+~==++=+=+=+-
1* 2* 5.5* 11* 6* 9 12* 18  6.5* 16* 19.5* 24* 28* 39* 117* 18 19.5 36 48 54
 6* 9 12* 18 24* 36 48 54           12* 24* 58.5* 18 36 48 54 526.5
 6* 9 12* 18 24* 36 48 54           12* 24* 58.5* 18 36 48 54 526.5
 6* 9 12* 18 24* 36 48 54           12* 24* 58.5* 18 36 48 54 526.5
       24* 36 48 54                           24* 36 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
     12* 18 24* 48 54                       24* 28* 18 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
 5.5* 11* 6 9 12 18 24 36         16* 117* 18 19.5 24 36 39 48 54 156
 5.5* 11* 18 24 36 48 54                16* 117* 18 24 36 48 54
 6* 9 12* 18 24* 36 48 54           12* 24* 58.5* 18 36 48 54 526.5
 5.5* 11* 18 24 36 48 54                16* 117* 18 24 36 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
     12* 18 24* 48 54                       24* 28* 18 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
     12* 18 24* 48 54                       24* 28* 18 48 54
 5.5* 11* 18 24 36 48 54                16* 117* 18 24 36 48 54
 6* 9 12* 18 24* 36 48 54             24* 28* 39* 18 19.5 36 48 54
```

We can see that some of the rates are different between the two columns. These should be identical.

If I use a different NIC (tested with the Intel AX200), the results are identical, rather than different.

This was discovered after I purchased a Lenovo Thinkpad T440p on eBay. It came with an Intel 7260 WLAN NIC.

This points to an issue with the Intel 7260 driver.

Driver Specs:

```
+ Driver: Intel(R) Dual Band Wireless-AC 7260
+ Vendor: Intel Corporation
+ Provider: Intel
+ Date: 9/3/2018
+ Version: 18.33.14.3
+ INF file: oem22.inf
+ Type: Native Wi-Fi Driver
```

System Specs:
 
```
+ OS Name: Microsoft Windows 10 Pro
+ OS Version: 10.0.18362 N/A Build 18362
+ Laptop: Thinkpad T440p
+ NIC: Intel 7260
+ System Manufacturer:       LENOVO
+ System Model:              20AWS43Y00
```

# Intel 7260 does not respect default Wireless LAN Service scan interval.

Discovered on 2019/07/08. I noticed that the Intel 7260 on my test system seems to initiate a scan every 5 seconds if not connected, or every 10 seconds if connected.

From the [Microsoft docs on WlanScan](https://docs.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanscan):

```
The current default behavior is that the Wireless LAN Service only asks the wireless interface driver to scan for wireless networks every 60 seconds, and in some cases (when already connected to wireless network) the Wireless LAN Service does not ask for scans at all. 
```

This could be a perf issue:

```
Since it becomes more difficult for a wireless interface to send and receive data packets while a scan is occurring, the WlanScan function may increase latency until the network scan is complete.
```

System specs:

```
+ OS Name: Microsoft Windows 10 Pro
+ OS Version: 10.0.18362 N/A Build 18362
+ Laptop: Thinkpad T440p
+ NIC: Intel 7260
+ System Manufacturer:       LENOVO
+ System Model:              20AWS43Y00
```

Driver Specs:

```
+ Driver: Intel(R) Dual Band Wireless-AC 7260
+ Vendor: Intel Corporation
+ Provider: Intel
+ Date: 9/3/2018
+ Version: 18.33.14.3
+ INF file: oem22.inf
+ Type: Native Wi-Fi Driver
```