Release History
===============

RELEASED
--------

0.5.0 (2026-10-27)
------------------

Breaking `--json` changes:

- `--watchevents --json` leaves out keys whose value is unknown instead of writing `null`, at every level of the record. Old: `"rssi": null`, `"old_ap_mld": null`, `"active": null`, `"stats": null`. New: the key is absent. `false` and `0` are still written. Read these keys with a default (#150).
- On Linux, the scan-finished `--watchevents` event is `scan_complete`, the name Windows uses. Old: `scan_cache_updated`, printed only with `--debug`. New: `scan_complete`, printed by default (#151).

Other changes:

- `-channel` prints the band and frequency of the connected channel. `-channel --json` gains `band` and `freq_mhz`. `-raw` output is unchanged (#149).
- On Linux, `--watchevents` prints `scan_started`, `scan_complete`, and `scan_aborted`, with the frequency and BSSID counts. `connected` gains `roam` and, for a roam, `roam_type` (`ft`, `pmksa`, `sae`, or `full`) and `roam_ms`. `port_authorized` gains `since_connect_ms` and `roam_total_ms` (#151).
- On Linux, a failed connect while associated no longer hides the next roam (#154). Fixes #153.
- On Linux, `--watchevents` prints `auth_failed` when the AP rejects authentication or authentication times out, and `assoc_failed` when association times out (#155). Fixes #122.
- `-exportraw` writes to the `-path` directory, or to the directory of a `.pcapng` path. An unusable `-path` stops lswifi before it scans (#156). Fixes #125.
- lswifi exits nonzero when it fails, including a missing interface, Ctrl+C, and a `-decode` or `-decoderaw` file it cannot read. It used to exit 0 (#158). Fixes #157.

0.4.0 (2026-10-26)
------------------

- VHT Operation channel width is 80, 160, or 80+80 from the centre frequency gap, including deprecated width values 2 and 3. When VHT Capabilities Extended NSS BW Support requires it, the second centre comes from HT Operation CCFS2. A 2.4 GHz BSS keeps its HT width. On 6 GHz, HE Operation width code 3 with no 160 MHz gap is 80 MHz, and a wider gap is 80+80. Only `channel_width` in the table, CSV, and `--json` changes (#145).
- `-ies` text decodes Wi-Fi 4/5/6 capability and operation fields: HT and VHT MCS maps per spatial stream, LDPC, short GI, STBC, beamforming, protection mode and CCFS2, VHT max MPDU and channel width, and HE TWT and beamforming flags. Summary columns and `--json` are unchanged (#146).
- On Linux MLO associations, `--get-interfaces` and `--watchevents` connected and roamed events take top-level channel, frequency, band, and width from the link carrying traffic instead of link 0 (#147). Fixes #129.
- `--get-interfaces` text marks the active link and prints per-link counters when the kernel sends them. `--get-interfaces --json` gains `ap_mld`. Each `links` entry gains `active` and `stats`. Connected and roamed `--watchevents` events gain `old_ap_mld`. JSON changes are additive (#147).
- Per-link station stats are requested on GET_STATION and the dump is retried without the link-stats attribute when the kernel rejects it (#147).

0.3.4 (2026-10-26)
------------------

- On macOS, when Location Services is not determined, the warning says to click Allow in the prompt and run lswifi again (#138).
- If that prompt never appears, the warning prints this Python's path and says to add it in System Settings > Privacy & Security > Location Services with the + button, turn it on, and run lswifi again (#139).
- EHT Operation (extension 106) decodes the parameter bits, the Basic EHT-MCS And NSS Set, and the disabled subchannel bitmap when that bit is set. A short element keeps the fields that fit and shows the rest as raw hex. An empty or truncated extension element no longer drops the rest of the information elements. Unknown extension IDs print as `Extension <id>` with the raw body (#140).
- EHT Capabilities (extension 108) decodes the MAC and PHY capability bits and the Supported EHT-MCS And NSS Set. Basic Multi-Link (extension 107) decodes the common information and prints simultaneous link counts. A short or inconsistent length stays inside the element (#141).
- A Reduced Neighbor Report lists every neighbor, including the TBTT Information Header on each one. Reserved TBTT lengths are raw hex. 20 MHz PSD is in dBm/MHz: 127 means no limit and -128 means the channel cannot be used (#142).
- Transmit Power Envelope count N is N+1 EIRP values for 20, 40, 80, and 160 MHz, and a following octet is 320 MHz. A PSD interpretation is one value for the whole BSS when N is 0, and one value per 20 MHz subchannel otherwise. PSD 127 means no limit and -128 means the channel cannot be used (#143).
- HE Operation prints the 6 GHz minimum rate, Duplicate Beacon, Regulatory Info, and BSS Color even when the color is 0. HE Capabilities reads BQR and PSR Responder from the correct bits, and `spatial_streams` is the larger of the <=80 MHz and 160 MHz counts. Extension element IDs in `--json` and CSV stay strings and sort numerically (#143).

0.3.3 (2026-10-25)
------------------

- On macOS, ask for Location Services authorization and name the state in a stderr warning. A code-signed Python such as the python.org build is required (#135, #133).
- `--get-interfaces` prints `Location Services:`, and `--get-interfaces --json` includes `location_authorization`.
- macOS depends on `pyobjc-framework-CoreLocation`.
- On macOS and Linux, derive PHY from information elements, so the PHY column is no longer blank in the table, JSON, and CSV. A 2.4 GHz network that advertises VHT shows `n`, and `-ies` still lists those elements (#136).
- CI tags and releases when the version changes on `main` (#134).

0.3.2 (2026-10-25)
------------------

- Require Python 3.11 or newer. The test suite also runs on Python 3.12.

0.3.1 (2026-10-24)
------------------

- Detect legacy WPA from vendor IE 221 (OUI 00:50:F2, type 1) in the auth, encryption, and security columns. Suites are merged when an RSN element is also present (#123).
- `--json` keeps every scan in `scan_data` as a flat list of BSS objects. A file from 0.3.0, where later scans were nested lists, is flattened on the next append. Rewriting the file no longer leaves trailing bytes that make it invalid (#127).
- On Windows, `--uptime` sorts by elapsed time. A BSS with no uptime sorts last. JSON and CSV use that same order.
- The AP uptime column is omitted from the table and from CSV on macOS and Linux. JSON still has `uptime`, set to null. `--uptime` is only a flag on Windows: on macOS and Linux it is absent from `--help` and from shell completion, and argparse rejects it. `--supported` says AP uptime isn't available.
- Interface text omits fields the platform cannot supply, including an empty GUID and an unsupported bus. JSON keeps those keys as null.
- Transmit and receive rates print as whole numbers when they have no fractional part (`576 Mbps`) and keep one decimal when they do (`6.5 Mbps`).
- Unknown RSSI is printed as `--`. It still sorts as the weakest signal and is not removed by `-t`.
- `-export` with `--channel-width 20` no longer includes 320 MHz networks. A width of `80+80` does not crash the filter.
- A short Extended Capabilities or vendor-specific element no longer fails that BSS. One BSS that still cannot be parsed is skipped instead of dropping the scan.
- `--json` rate lists are `[]` when an AP advertises no rates.
- `--get-interfaces` on macOS shows more of the connected interface from CoreWLAN: PHY mode, security, MCS, spatial streams, transmit power, interface mode, power, an ARP-resolved gateway, the IPv4 address, and supported channels. Fields the platform cannot supply are omitted. JSON keeps those keys as null.
- `--get-interfaces` on Linux shows nl80211 link stats and supported channels, including transmit and receive rates, signal, counters, channel busy, and PHY generations.
- Linux MLO associations list each link in `--get-interfaces` and `--watchevents`: id, AP BSSID, STA link address, frequency, channel, band, width, center, and transmit power when the kernel sent them. `--watchevents` takes frequency, channel, and width from the association link, calls the MLD address `ap_mld` in the text and the JSON, and omits the kernel's 0 dBm MLD signal.
- A link added or removed, or a channel switch that names a link, is a per-link `--watchevents` event rather than a roam or a channel change of the whole connection.
- `--get-interfaces --json <file>` writes that file. `--json` with no path still prints to stdout. One interface is one JSON object. More than one interface is one JSON list, the same document in the file and on stdout.
- Linux 5 GHz text keeps a standard 20 MHz run together and lists off-raster channels after it, for example `36-64, 100-144, 149-165 (also 34, 38, 42, 46)`. 6 GHz summaries stay in channel order. JSON still includes every channel the driver reports.

0.3.0 (2026-10-23)
------------------

- Add Linux support through an nl80211 (generic netlink) backend built on the standard library. No new dependencies.
- Linux: triggering a scan needs root (`CAP_NET_ADMIN`). Without it, `lswifi` warns and shows the kernel's cached results.
- Linux: scan 2.4, 5 and 6 GHz. When the adapter lists a 6 GHz band, also probe 6 GHz APs found in Reduced Neighbor Reports.
- Linux: `--list-interfaces` and `--get-interfaces` (with `--json`), and mark the connected BSS.
- Linux: `--watchevents`, including `--json`, for connect, failed connect, roam, disconnect, port authorized and channel switch.
- `--supported` is not available on Linux.
- Unknown RSSI (drivers that report no dBm) sorts weakest and is not dropped by `-t`.
- Package metadata lists Linux.

0.2.1 (2026-10-23)
------------------

- macOS: install PyObjC CoreWLAN by default. Plain `pip install lswifi` works; no `lswifi[macos]` extra needed (kept as an alias).
- Package metadata lists macOS.

0.2.0 (2026-10-23)
------------------

- Add macOS support through a CoreWLAN backend. Install with `lswifi[macos]`. Needs Location Services on a signed Python such as the python.org build.
- Split platform code into backends under `lswifi/backends/`. Windows behavior is unchanged.
- Add `--watchevents` on macOS, including roams, sleep/wake and airportd deauth reasons.
- Add `--watchevents --json` NDJSON event output on macOS and Windows.

0.1.67 (2026-10-21)
-------------------

- Require Python 3.13 or newer.
- Run the test suite on Windows in GitHub Actions for Python 3.13 and 3.14.
- Publish releases to PyPI from GitHub Actions with Trusted Publishing.
- Update development and build dependencies, including PyInstaller 6.22.3 and mypy 2.4.0.

0.1.66 (2026-03-10)
-------------------

- Fix country IE parsing to extract only the two-character ISO 3166-1 country code and ignore the third octet.

0.1.65 (2026-03-10)
-------------------

- Add `-d`/`--country` flag to display two-letter country code (CC) from the 802.11d IE found in scan results.

0.1.64 (2026-03-09)
-------------------

- JSONify more output support for --get-interfaces, --list-interfaces, -ap, -channel, and -rnr commands via --json flag.

0.1.63 (2026-03-09)
-------------------

- Fix AP Health IE bit field parsing

0.1.62 (2026-01-30)
-------------------

- Fix PowerShell completions

0.1.61 (2026-01-14)
-------------------

- Add BSS membership selector support to rate parsing
- Fix -export BSSID filtering and improve pcap file handling
- Improve --get-interfaces USB speed detection using Windows IOCTL instead of PowerShell property

0.1.60 (2026-01-13)
-------------------

- Migrate tooling to ruff and add more tests
- Improve --get-interfaces output with additional connection details

0.1.59 (2026-01-12)
-------------------

- Add Alcatel-Lucent AP name parsing
- Add PowerShell tab completion
- Fix channel width filtering for 320 MHz

0.1.58 (2026-01-08)

- Add MikroTik/Routerboard AP name parsing
- Add Management MIC element (IE 76) parsing support
- Fix Aerohive AP name parsing
- Improve pcap/pcapng decoding

0.1.57 (2026-01-06)
-------------------

- Add Cisco AP Name v2 support; prefer v2 over CCX v1 when both are present
- Add Ubiquiti AP name parsing
- Add Meter AP name parsing

0.1.56 (2025-08-18)
-------------------

- Removes --pmf arg as PMF column is included by default
- Increase scan timeout to 7 seconds
- Improve RNR parsing when reported neighbor BSSes are in 2.4/5 GHz

0.1.55 (2025-08-15)
-------------------

- Fix RNR parsing when reported neighbor BSSes are in 2.4/5 GHz

0.1.54 (2025-08-07)
-------------------

- Fix channel parsing error for 160 MHz CBW

0.1.53 (2025-07-22)
-------------------

- Improve RNR decoding for Wi-Fi 7

0.1.52 (2025-06-09)
-------------------

- Fix AP health IE (again)

0.1.51 (2025-06-05)
-------------------

- Fix AP health IE

0.1.50 (2025-05-13)
-------------------

- Fixed Python 3.9 compatibility by replacing datetime.UTC with datetime.timezone.utc

0.1.49 (2025-05-12)
-------------------

- Add import/export for pcapng files using `-export` arg.
- Add AP health IE for HPE Aruba Networking.

0.1.48 (2025-04-23)
-------------------

- Add GPS ellipse IE for HPE Aruba Networking.

0.1.47 (2025-01-07)
-------------------

- Fixed buffer overflow crash in interface enumeration by dynamically allocating buffer size instead of using fixed limit (introduced in 0.1.46).

0.1.46 (2024-12-31)
-------------------

- Fixed a crash occurring when mapping an interface GUID to a physical address on systems with certain administrative language settings.
- Drop support for Python 3.7-3.8

0.1.45 (2024-07-02)
-------------------

- Rename cipher suite 00-0F-AC:4 from `AES` to `CCMP-128` to 1) match IEEE meaning and 2) with Wi-Fi 7 networks we will start to see GCMP-256 too, finally.
- Split security column into 3 columns separating authentication, encryption, and PMF into their own

0.1.44 (2024-06-27)
-------------------

- Rename AKM labels for concision and to match labels found in WFA deployment guide
- Add Management MIC (MME) to IE dictionary
- Add TWT Information Extension to Extension IE dictionary

0.1.43 (2024-03-25)
-------------------

- Remove debug print statement added in 0.1.42

0.1.42 (2024-03-25)
-------------------

- Fix MAC address detection for certain WLAN interfaces
- Fix 320 MHz channel detection in 6 GHz for Wi-Fi 7

0.1.41 (2023-09-22)
-------------------

- Suppress syslog errors

0.1.40 (2023-09-15)
-------------------

- Update vendor OUIs hash
- Fix Wi-Fi 7 PHY detection

0.1.39 (2023-08-17)
-------------------

- Update vendor OUIs hash

0.1.38 (2023-07-18)
-------------------

- Fix crash

0.1.37 (2023-07-17)
-------------------

- Improve --watchevent output for .1X networks
- Syslog for --watchevent output with --syslog <server ip>
- Add to vendor OUIs hash
- Don't parse IEs if we are printing bytes to screen

0.1.36 (2023-03-06)
-------------------

- ASCII art
- Update 00:0F:AC:1 mapping from FT-.1X to FT-.1X-SHA256 per IEEE 802.11-2020

0.1.35 (2023-02-25)
-------------------

- Improve --watchevent output
- Add another vendor for AP name parsing
- Minor cosmetic changes

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
