Release History
===============

UNRELEASED
----------

0.1.35 (2023-02-25)
-------------------

- Improve --watchevent output
- Add another vendor for AP name parsing

0.1.34 (2023-02-22)
-------------------

- Improve --watchevent output by adding BSSID and RSSI to roaming start and roaming end events  

0.1.33 (2023-02-21)
-------------------

- Print warning if no interfaces are detected
- Print warning if the scan fails
- Only wrap lines with text exceeding window size
- Fix crash when decoding raw byte file with RNR IE present
- Fix crash when decoding raw byte file with an IE without a parser
- Improve --watchevent output with RSSI values where possible for certain events
- Begin adding support for 802.11be (EHT) / Wi-Fi 7
- 802.1X becomes .1X to conserve whitespace in Security column
- Increase scan timeout interval from 4 seconds to 5

0.1.32 (2022-11-22)
-------------------

- Improve specificity on threshold option (value from user must be from -1 to -100)
- Add `-all` option to remove threshold filtering which excludes results with weak signals
- Add `-rnr` option to display an alternate set of columns based on information from the Reduced Neighbor Report IE.

0.1.31 (2022-11-16)
-------------------

- Fix traceback and decoding error when getmac.exe contains special characters

0.1.30 (2022-11-15)
-------------------

- Updates to the Vendor OUI table
- Handle traceback when running getmac.exe fails to map interface to physical address

0.1.29 (2022-10-14)
-------------------

- Add `-n|--scans #` option to set a number of scans to perform before exit
- Add `--time #` option to perform repeated scans for a given number of seconds
- Add `-i|--interval #` option to set the number of seconds to wait between scans
- Add support for JSON output to file
- Add support for CSV output to file
- Add support for identifying several Vendor OUIs
- Add experimental concurrency for when multiple scanning interfaces are present
- Changed frequency unit type from MHz (2412) to GHz (2.412)
- Improved several debug outputs
- Minor bug fixes

0.1.28 (2022-08-06)
-------------------

- Fix sorting problem introduced by rearranging columns in 0.1.27

0.1.27 (2022-08-05)
-------------------

- Enable optional argument for Management Frame Protection column (--pmf or --mfp)

0.1.26 (2022-08-05)
-------------------

- Improve RSN handling with a detected network is using AKM 0 and group cipher 0.

0.1.25 (2022-08-05)
-------------------

- Version mishap

0.1.24 (2022-08-05)
-------------------

- Fix AKM suite bug

0.1.23 (2022-04-26)
-------------------

- RSN parsing enhancements for WPA3

0.1.22 (2022-02-16)
-----------

- Add --tpc column to output
- Add beacon --interval column to output

0.1.21 (2022-02-13)
-------------------

- Happy Super Bowl LVI and Valentine's Day!
- Adds --qbss option to add QBSS STA # and CU columns to output

0.1.20 (2022-01-31)
-------------------

- Fix 5 GHz filter which was incorrectly filtering 6 GHz channels 1, 5, 9 as 5 GHz channels
- Don't store control characters in the local AP name cache
- Update System Error Codes enumeration to suppress an error which occurs when no valid WLAN adapters are available on run

0.1.19 (2021-10-29)
-------------------

- Fix crash when utf-8 decode fails on discovered SSIDs

0.1.18 (2021-09-28)
-------------------

- Improvements to 6 GHz channel width detection
- Add two more vendors for AP name parsing
- Escape control characters by default for detected SSIDs and AP names

0.1.17 (2021-08-25)
-------------------

- Fix NSS detection when 6 GHz channel width is 20 MHz

0.1.16 (2021-08-25)
-------------------

- Improved detection of 6 GHz channel widths

0.1.15 (2021-08-03)
-------------------

- Improved parsing of RNR

0.1.14 (2021-07-29)
-------------------

- Add parser for Wi-Fi Alliance OWE Transition Mode 
- Fix channel parsing bug when HE IEs are present
- Improve handling client interfaces

0.1.13 (2021-05-08)
-------------------

- Fix output when using band filters

0.1.12 (2021-04-26)
-------------------

- More 6E bug fixes

0.1.11 (2021-04-25)
-------------------

- 6E bug fixes, minor changes

0.1.10 (2021-04-24)
-------------------

- interworking, tx power envelope, MBO, minor cosmetic stuff

0.1.9 (2021-04-21)
------------------

- fix crash when channel frequency > 7000
  
0.1.8 (2021-04-18)
------------------

- basic Wi-Fi 6E detection
- add timeout scan complete takes longer than 4 seconds
- minor changes

0.1.6 (2021-01-04)
------------------

- fix issue with client mac and bssid not displaying when bouncing interface during `--watchevents`

0.1.5 (2021-01-04)
------------------

- display client MAC instead of GUID and add BSSID when available to all events when using `--watchevents`

0.1.4 (2021-12-29)
------------------

- add AP BSSID to output on associated wlan events when using `--watchevents`

0.1.3 (2020-12-28)
------------------

- expand json support
- refactor

0.1.2 (2020-12-27)
------------------

- add support to display results in json with --json arg

0.1.1 (2020-09-14)
------------------

- fix issue when running with --ap-names arg

0.1 (2020-09-09)
------------------

- conception of public beta
