Information Elements:
=====================

Mobility Domain (MDIE)
----------------------

The AP uses the MDIE to advertise that it is included in a group of APs that constitute a mobility domain, to advertise it's support for the FT capability, and to advertise it's FT policy information.

```
IE #: 54
Length: 3
Fields:

  - Mobility Domain Identifier (MDID)
  - FT Capability and Policy:
    + Fast BSS Transition over DS
    + Resource Request Protocol Capability

MDIE Format:

|         | Element ID | Length | MDID | FT Capability and Policy |
| Octets: | 1          | 1      | 2    | 1                        |

FT Capability and Policy Field Format:

|       | B0                          | B1                                   | B2    B7 |
|       | Fast BSS Transition over DS | Resource Request Protocol Capability | Reserved |
| Bits: | 1                           | 1                                    | 6        |

If B0 == 0:
    Over-the-Air Fast BSS Transition

If B0 == 1:
    Over-the-DS Fast BSS Transition
```

Client Capability Logic:
========================

802.11 security
---------------

`opensystem/wpa2-aes/wpa2-psk-aes/wpa-tkip/wpa-psk-tkip/wpa-tkip,wpa2-aes/wpa-psk-tkip,wpa2-psk-aes/static-wep/dynamic-wep/mpsk-aes/enhanced-open/wpa3-sae-aes/wpa3-aes-ccm-128/wpa3-cnsa`

- opensystem
- enhanced-open
- static-wep
- dynamic-wep
- wpa-tkip
- wpa-psk-tkip
- wpa-tkip
- wpa2-aes
- wpa2-psk-aes
- mpsk-aes
- wpa3-sae-aes
- wpa3-aes-ccm-128
- wpa3-cnsa (192-Bit - Optional)

RSNE (IE 48)

https://www.wi-fi.org/discover-wi-fi/security

- WPA3 Enterprise 802.1X (optional) 192-bit (with CNSA) `Version: 1, Group: 00:0f:ac 802.1X-Suite-B-SHA-384, Pairwise: GCMP-256, AKM: GCMP-256`
- WPA3 Enterprise 802.1X 
- WPA3 Personal - Simultaneous Authentication of Equals (SAE)
- WPA2 Enterprise 802.1X
- WPA2 (AES)
- WPA2/WPA (AES/TKIP)
- WPA (TKIP)
- WEP
- OWE - SAE https://tools.ietf.org/html/rfc8110
- Open - No encryption/no authentication

## PFM (Protected Management Frames) Column

Management Frame Protection Required/Capable are inside the RSN Capabilities tag which is a subfield of the RSNE:48.

- Capable/Supported/Optional (MFPC = 1)
    + Both 802.11w capable clients and non-capable clients can connect.
- Required/Mandatory (MFPR = 1)  
    + Only 802.11w capbale clients can associate.
- Empty (MFPC/R = 0, or MFP not supported)
    + Disables 11w PMF protection

Pre-WPA3: PMF only works with WPA2-PSK or 802.1X WPA2-Enterprise. 

## WPA3-SAE (Personal)

The WPA2 PSK method is replaced with "Simultaneous Authentication of Equals" (SAE) for more robust password-based authentication. 

WPA3 uses "MFP required" mode with SHA-256 for hashes. 

The passphrase is no longer used for key derivation and instead the key derivation is based on "Elliptic Curve Cryptography" (ECC).

```
When a BSS is configured in WPA3-SAE Mode, PMF shall be set to required (MFPR bit in the RSN Capabilities field shall be set to 1 in the RSNE transmitted by the AP)
A WPA3-SAE STA shall negotiate PMF when associating to an AP using WPA3-SAE Mode
```

Mandatory:

- Does not allow for TKIP or WEP. 
- AES is mandatory.

WPA3 uses the “Management Frame Protection Required” mode with SHA-256 [2] for Hashes.

WPA3 will be mandatory for 802.11ax (High Efficiency) 

### WPA3-SAE Transition Mode

```
When WPA2-PSK and WPA3-SAE are configured on the same BSS (mixed mode), PMF shall be set to capable
(MFPC (capable) bit shall be set to 1, and MFPR (required) bit shall be set to 0 in the RSN Capabilities field in the RSNE transmitted
by the AP)
- When WPA2-PSK and WPA3-SAE are configured on the same BSS (mixed mode), the AP shall reject an
association for SAE if PMF is not negotiated for that association
- A WPA3-SAE STA shall negotiate PMF when associating to an AP using WPA3-SAE Transition Mode
```

WPA3 Transition Mode allows WPA2 and WPA3 at the same time on the same SSID. 
 - This makes the SSID only require PMF optional. So this is still prone to WPA2 attacks.

## WPA3-Enterprise

```
WPA3-Enterprise 192-bit Mode requirements
1. When WPA3-Enterprise 192-bit Mode is used by an AP, PMF shall be set to required (MFPR bit in the RSN
Capabilities field shall be set to 1 in the RSNE transmitted by the AP).
2. When WPA3-Enterprise 192-bit Mode is used by a STA, PMF shall be set to required (MFPR bit in the RSN
Capabilities field shall be set to 1 in the RSNE transmitted by the STA).
3. Permitted EAP cipher suites for use with WPA3-Enterprise 192-bit Mode are:
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- ECDHE and ECDSA using the 384-bit prime modulus curve P-384
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- ECDHE using the 384-bit prime modulus curve P-384
- RSA ≥ 3072-bit modulus
- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
- RSA ≥ 3072-bit modulus
- DHE ≥ 3072-bit modulus
```

Mandatory:
- WPA3-Enterprise = WPA2-Enterprise + PMF. 

The mandatory part of WPA3-Enterprise should also be easy to implement since it is just WPA2-Enterprise together with PMF.

Optional:
- 192-bit security (Suite-B CNSA)
- Clarify that WPA3-Enterprise (without 192-bit mode) has the option of PMF optional or required.

WPA3-Enterprise is WPA2-Enterprise + (PMF optional/required). No use of SAE/ECC in WPA3-Enterprise. 

WPA3-Enterprise + (optional) 192-bit requires upgrade and needs to be set up correctly. 
 - A 192-bit 802.1X SSID should be seperated/encapsulated from other traffic in your network.
 -Otherwise, someone could look for the weakest link by looking at other SSIDs connected to the same network and attack them. 

## WPA2

Allows AES and TKIP in mixed mode WPA/WPA2. 
- Remember 11n and 11ac only offer high throughput with AES enabled. TKIP handicaps. 

## WPA

802.11 phy
-----------

1. 802.11a (OFDM):
    a. are HT, VHT, or HE parameters present?
        Y - not 802.11a
        N - maybe 802.11a?
2. 802.11b (HR-DSSS):
    a. are ERP, HT, VHT, or HE parameters present?
        Y - not 802.11b
        N - maybe 802.11b?
3. 802.11g (ERP):
    a. are HT, VHT, or HE parameters present?
        Y - not 802.11g
        N - maybe 802.11g?
4. 802.11n (HT): inspect tagged parameter number 45 (HT Capabilities)
    a. is tagged parameter present? 
        Y - 802.11n supported
        N - 802.11n not supported
    b. inspect octets 3 to 7 (Rx MCS sets) - 
        i. count Rx MCS bitmasks that are set (11111111) to determine number of streams supported
5. 802.11ac (VHT): inspect tagged parameter 191 (VHT Capabilities)
    a. is tagged parameter present?
        Y - 802.11ac supported
        N - 802.11ac not supported
    b. inspect octets 4 & 5 (Rx MCS map) - 
        i. count Rx MCS map bit pairs set to '10' to determine number of streams supported
    c. inspect octet 1 (one of the four vht capability octets)
        i. if bit zero set to '1', client is SU Beam-formee capable
    c. inspect octet 2 (one of the four vht capability octets)
        i. if bit zero set to '1', client is MU Beam-formee capable        
6. 802.11ax (HE): inspect tagged parameter 255 (Extension Information Element) and EID HE 35 (HE Capabilities) or EID HE 36 (HE Operation) are present

802.11 amendments
-----------------

1. 802.11d - inspect information element ID 7 (Country Information)
    - a. is tagged parameter present?
       + Y - 802.11d supported
       + N - 802.11d not supported
2. 802.11e - inspect information element ID 11 (QBSS load)
    - a. is tagged parameter present?
        + Y - 802.11e supported
        + N - 802.11e not supported 
3. 802.11h - inspect information element ID 32 (Power Constraint)
    - a. is tagged parameter present?
       + Y - 802.11h supported
       + N - 802.11h not supported
4. 802.11i - inspect information element ID 48 (RSN Information)
    - a. is tagged parameter present?
        + Y - 802.11i supported
        + N - 802.11i not supported
5. 802.11k: inspect tagged parameter 70 (RM Enabled Capabilities) - RM = radio management
    - a. is tagged parameter present?
        + Y - 802.11k supported
        + N - 802.11k not supported
6. 802.11r - inspect tagged parameter 54 (Mobility Domain)
    - a. is tagged parameter present? 
        + Y - 802.11r supported
        + N - 802.11r not supported
7. 802.11s - inspect tagged parameter 113 (Mesh Configuration)
    - a. is tagged parameter present? 
        + Y - 802.11s supported
        + N - 802.11s not supported
8. 802.11v - inspect tagged parameter 127 (Extended capabilities)
    - a. **is tagged parameter present?**
        + N - 802.11v not supported
        + Y - 802.11v may be supported
            - **b. does octet 3 exist in ext capabilities tagged parameter?**
                + N - 802.11v not supported
                + Y - 802.11v may be supported
                    - **c. is bit 3 of octet 3 set to '1'?**
                        + Y - 802.11v is supported
                        + N - 802.11v not supported
9. 802.11w - inspect information element ID 48 (RSN information)
    - a. is tagged present?
        + N - 802.11w not supported
        + Y - 802.11w may be supported
            - **b. is B6 (MFPR) of the RSN capabilities set to '1'?**
                + Y - 802.11w supported. 
            - **c. is B7 (MFPC) of the RSN capabilities set to '1'?**
                + Y - 802.11w supported. **802.11w MFP capable.**
            - **d. is B6 and B7 (MFPR/MFPC) of the RSN capabilities both set to '1'?**
                + Y - 802.11w supported. **802.11w MFP required.**
            - **e. is B6 and B7 (MFPR/MFPC) of the RSN capabilities both set to '0'?**
                + N - off/not supported
10. 802.11u - inspect information element ID
    - a. is tagged present?
        + N - 802.11u not supported
        + Y - 802.11u is supported

For 11w (Management Frame Protection - RSN Capabilities in IE 48):

- *MFPR: Management Frame Protection Required*
- *MFPC: Management Frame Protection Capable*
- MFPR 1 + MFPC 1 = Required
- MFPR 0 + MFPC 1 = Capable
- MFPR 0 + MFPC 0 = Off

802.11 other
------------

1. Max Power - inspect tagged parameter 33 (Power Capability)
    a. is tagged parameter present?
        N - unable to report max power
        Y - inspect octet 1 of tagged parameter (max powe rin dBm)

2. Supported channels - inspect tagged parameter 6 (Supported Channels)
    a. Step through each channel set octet-pair provided reporting start channel and other channels in range
        i. Note: use step of 4 if start channel above number 14 (must be 5GHz channels), use step of 1 otherwise

WPS
---

WPS is IE 221, OUI 00-50-F2 (Microsoft), and Type 4 (00-50-F2-04)

WPS contains Device Names which could be used as the AP Name.

AP Names
--------

# Introduction

AP names are typically listed in the vendor specific IE (221). An outlier is the Cisco Aironet IE. This IE allows nonstandard, vendor-specific information to be sent in this IE of the beacon frame. It's format is as follows. 

| field: element id | length | organization identifier | vendor specific content    |
| ----------------- | ------ | ----------------------- | -------------------------- |
| octet: 1          | 1      | j                       | variable                   |

According to 802.11-2016, `j` can be either an OUI24 (24-bit) or an OUI36 (36-bit)

However, The OUI-36 is a registry activity name, which was replaced by the MA-S registry product name as of January 1, 2014. It includes both a unique 36-bit number used in some standards and the assignment of a block of EUI-48 and EUI-64 identifiers by the IEEE Registration Authority. The owner of a previously assigned OUI-36 registry product may continue to use the assignment.

OUI-36 links: https://macaddress.io/faq/what-is-a-36-bit-organizationally-unique-identifier-oui-36

I'm not aware of actual OUI-36 use, and I have not seen it in the wild.

## Aruba *TESTED*

- Element ID: 221
- OUI: 00-0B-86
- Type: 1
- Payload: Subtype (1) + Offset (1) + AP Name
- Raw `b'\x00\x0b\x86\x01\x03\x00Josh_Schmelzle'`
- Vendor OUI and Type `b'\x00\x0b\x86\x01` payload `[\x03\x00Josh_Schmelzle']`

| OUI          | Type  | Subtype | Offset:1 | Data            |
| ------------ | ----- | ------- | -------- | --------------- |
| \x00\x0b\x86 | \x01\ | \x03    | \x00     |  Josh_Schmelzle |

Suggested parsed output: `Vendor Specific: Aruba: AP Name (Josh_Schmelzle)`

## Ruckus

N/A no support at this time

## Extreme (IdentiFi)

- Element ID: 221
- OUI: 00-0f-bb
- Type: 4
- Payload: Subtype (1) + Offset (1) + AP Name
- Raw `b'\x00\x0f\xbb\x04\x00\x4d\x38\x61\x63'`
- Vendor OUI and Type `b'\x00\x0f\xbb\x04` payload `\x00\x4d\x38\x61\x63`

| OUI          | Type  | Offset:1 | Data             |
| ------------ | ----- | -------- | ---------------- |
| \x00\x0f\xbb | \x04\ | \x00     | \x4d\x38\x61\x63 |

Decoded AP name data is `M8ac`

Deployment Notes:

- the LEDs must be set to identify for it to broadcast https://gtacknowledge.extremenetworks.com/articles/How_To/How-to-have-an-Access-Point-Name-show-up-in-beacons-for-a-site-survey-report 
- the Aircheck G2 will replace the BSSID with the AP name if it’s there. 


## Extreme (Zebra) *TESTED*

- Element ID: 221
- OUI: 00-a0-f8
- Type: 1
- Payload: Unknown (7 bytes) + AP Name Length (1 byte) + AP Name
- Raw `b'\x00\xa0\xf8\x01\x03\x01\x0f\xc0\x00\x00\x00\x12ap8533.meade.local'`
- Vendor OUI and Type `[b'\x00\xa0\xf8\x01]` payload `[\x03\x01\x0f\xc0\x00\x00\x00\x12ap8533.meade.local']`

| OUI          | Type  | Offset: 7 (unknown)          | Length | Data               |
| ------------ | ----- | ---------------------------- | ------ | ------------------ |
| \x00\xa0\xf8 | \x01\ | \x03\x01\x0f\xc0\x00\x00\x00 | \x12   | ap8533.meade.local |

Suggested parsed output: `Vendor Specific: Extreme (Zebra): AP Name (ap8533.meade.local)`

Note: Extreme has two Wi-Fi product lines. The (Zebra) distinction is important. One is WiNG which was originally developed by Symbol. Aquired by Motorola. Acquired by Zebra. Acquired by Extreme.

## Cisco CCX1 CKIP + Device Name (IE:113) *TESTED*

From WCS manual:

    > If Aironet IE support is enabled, the AP sends an Aironet IE 0x85 (which contains the access point name, load, number of associated clients, and so on) in the beaocn and probe responses of this WLAN, <REDACTED>

The name of the device starts at offset 10 and is up to 15 or 16 bytes in length, \0 padded.

    > /* A cisco AP transmits the first 15 bytes of the AP name, probably followed by '\0' for ASCII termination */

| IE           | 133                           |
| ------------ | ----------------------------- |
| Tag Name     | Cisco CCX1 CKIP + Device Name |
| Offset       | 10 bytes                      |
| Device Name  | 15 bytes + 1 (\0 padding)     |
| Stations     | 1 byte                        |
| Offset2      | 3 bytes                       |

Example:

- Element ID: 133
- Payload: Unknown (10 bytes) + AP Name Length (15 byte) + \0 padding + Client Count (1 byte) + unknown (3 bytes)
- Raw `b'\x00\x00\x8f\x00\x0f\x00\xff\x03Y\x00schmelzle_3702_\x00\x00\x00\x00L'`
- Unknown `b'\x00\x00\x8f\x00\x0f\x00\xff\x03Y\x00` + AP Name `schmelzle_3702_\x00` + Client Count `\x00` + Unknown `\x00\x00L`

| Unknown | AP Name | Client Count | Unknown |
| ------- | ------- | ------------ | ------- |
| \x00\x00\x8f\x00\x0f\x00\xff\x03Y\x00 | schmelzle_3702_\x00 | \x00 | \x00\x00L |

### Using Wireshark Source Code as reference

- epan/oui.h - contains OUI value
- epan/oui.c - contains label for OUI value
- epan/dissectors/packet-ieee802.11c

## Mist 

On the computer this was captured on, this frame is fine, but on their laptop it shows as a malformed packet, same with mine. Regardless, the data is there. 

The AP name is `ap41-1` and the Hex is `617034312d31`

- Element ID: 221
- OUI: 5c-5b-35
- Type: 1
- Payload: AP Name
- Vendor OUI and Type `[b'\x5c\x5b\x35\x01]` payload `[\x61\x70\x34\x31\x2d\x31']`

| OUI          | Type  | Data               |
| ------------ | ----- | ------------------ |
| \x5c\x5b\x35 | \x01\ | ap41-1             |

## Aerohive

N/A

QoS
---

PCF never took off. DCF/WMM did. EDCA is required.

WPS
---

```
Element ID: 221
    OUI: 00-50-F2 (Microsoft)
    Type: 4 (WPS)
    Version:
    Wi-Fi Protected Setup State:
    UUID-E
    RF Bands:
    Vendor Extension
        Vendor ID
        Vendor Data
```

WMM/WME
-------

The WMM specification defines two information elements for beacon frames. 

Each beacon frame transmitted by a WMM-enabled AP will contain either a `WMM Information Element`, or a `WMM Parameter Element`.

## WMM/WME Information Element

| Field 	 	 | Value 	| Octets |
| -------------- | -------- | ------ |
| Element ID 	 | 221 		| 1 	 |
| Length 	 	 | 7 		| 1 	 |
| OUI 		 	 | 00:50:f2 | 3 	 |
| OUI Type 	 	 | 2 		| 1 	 |
| OUI Subtype 	 | 0 		| 1 	 |
| Version 	 	 | 1 		| 1 	 |
| QoS Info Field | 1 		| ?	     |

## WMM/WME Parameter Element

| Field 		 | Value		  | Octets |
| -------------- | -------------- | ------ |
| ElementID 	 | 221			  | 1      |
| Length 		 | 24 			  | 1      |
| OUI 			 | 00:50:f2  	  | 3      |
| OUI Type 		 | 2 			  | 1      |
| OUI Subtype 	 | 1 			  | 1      |
| Version 		 | 1 			  | 1      |
| QoS Info Field | 1 			  | 1      |
| Reserved 		 | 1 			  | 1      |
| AC Parameters  | BE, BK, VI, VO | 16     |  


### Parameter Element Fields:

- Element ID: 221
- OUI: 00-50-F2 (Microsoft)
- Type: 2 (WMM/WME)

- WMM Subtype:
- WMM Version
- WMM QoS Info:
    + U-APSD
    + ParameterSetCount
    + Reserved
- Access Category - Best Effort (BE)
    + ACI AIFSN
        - ACI
        - Admission Controller Mandatory
        - AIFSN
        - Reserved
    + ECW
        - ECW Max
        - ECW Min
    + TXOP Limit
- Access Category - Background (BK)
    + `<see BE fields for format>`
- Access Category - Video (VI)
    + `<see BE fields for format>`
- Access Category - Voice (VO)
    + `<see BE fields for format>`

### AC (Access Category)parameter

Each AC parameter record (BE, BK, VI, and VO) has the following format:

| Octets: 1 |             1 |          2 |
| --------- | ------------- | ---------- |
| ACI/AIFSN | ECWmin/ECWmax | TXOP Limit |

#### ACI/AIFSN subfield:

| 7        | 6 5 | 4   | 3   0 |
| -------- | --- | --- | ----- |
| Reserved | ACI | ACM | AIFSN |

#### CWmin/ECWmax subfield:

| 7 4    | 3  0   |
| ------ | ------ |
| ECWmax | ECWmin |

> The fields ECWmin and ECWmax encode the values of CWmin and CWmax respectively in an
17 exponent form. The values ECWmin and ECWmax are defined such that:

> `CWmin = 2^ECWmin - 1`

> `CWmax = 2^ECWmax - 1`

> Hence the minimum encoded value of CWmin is 0, and the maximum value is 32767.

e.g.:

- ECWmin/ECWmax: 4/10 (CWmin/max 15/1023)
- ECWmin/ECWmax: 4/10 (CWmin/max 15/1023)
- ECWmin/ECWmax: 3/4 (CWmin/max 7/15)
- ECWmin/ECWmax: 2/3 (CWmin/max 3/7)

#### TXOP

`The value of TXOP limit is specified as an unsigned integer, with the least significant octet transmitted first, in units of 32 microseconds. A TXOP limit value of 0 indicates that a single MPDU, in addition to a possible RTS/CTS exchange or CTS to itself, may be transmitted at any rate for each TXOP. The value of the ACI references the AC to which all parameters in this record correspond. The mapping between AC index (ACI) and AC is defined in Table 6. The AIFSN value indicates the number of time slots inside the Arbitration Interframe space to be used. The minimum value for AIFSN shall be 2.
`

ACI to AC coding:

| ACI | AC    | Access Category  |
| --- | ----- | ---------------- |
| 00  | AC_BE | Best Effort (BE) |
| 01  | AC_BK | Background (BK)  |
| 10  | AC_VI | Video (VI)       |
| 11  | AC_VO | Voice (VO)       |
