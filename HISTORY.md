Release History
===============

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
