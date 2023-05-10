# Encoding Base64 string and decoding with lswifi

Python example:

```bash
import base64
f = open("out.ies", "wb")
f.write(base64.b64decode("AAlpbnRyYVdMQU4BCIKEiwwSlhgkAwEGLRosGBv///8AAAAAAAAAAAAAAAAAAAAAAAAAADAUAQAAD6wEAQAAD6wEAQAAD6wBKAAyBDBIYGw9FgYABQAAAAAAAAAAAAAAAAAAAAAAAACWBgBAlgAHAN0YAFDyAQEAAFDyBAEAAFDyBAEAAFDyAQAA"))
f.close()
```

Confirming:

```bash
cat out.ies
        intraWLAN���
�$-,��0���(20H`l=�@��P�P�P�P�
```

Decoding with lswifi:

```bash
lswifi -decode .\out.ies
Raw Information Elements (138 bytes):
00 09 69 6E 74 72 61 57 4C 41 4E 01 08 82 84 8B 0C 12 96 18 24 03 01 06 2D 1A 2C 18 1B FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 14 01 00 00 0F AC 04 01 00 00 0F AC 04 01 00 00 0F AC 01 28 00 32 04 30 48 60 6C 3D 16 06 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 96 06 00 40 96 00 07 00 DD 18 00 50 F2 01 01 00 00 50 F2 04 01 00 00 50 F2 04 01 00 00 50 F2 01 00 00

Decoded Information Elements:
Length    ID   Information Element       Raw Data                                                                       Decoded
9 bytes   0    SSID                      69 6E 74 72 61 57 4C 41 4E                                                     Length: 9, SSID: intraWLAN
8 bytes   1    Supported Rates           82 84 8B 0C 12 96 18 24                                                        1(B), 2(B), 5.5(B), 6, 9, 11(B), 12, 18 Mbit/s
1 bytes   3    DSSS Parameter Set        06                                                                             6
26 bytes  45   HT Capabilities           2C 18 1B FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Supported Channel Width Set: False
                                                                                                                        Spatial Streams: 3
20 bytes  48   RSN Information           01 00 00 0F AC 04 01 00 00 0F AC 04 01 00 00 0F AC 01 28 00                    Version: 1, AKM: 00:0F:AC .1X (1), Pairwise/Unicast: AES (4), Group: AES (4)
                                                                                                                        RSN Capabilities: 0x0028, PMF Capable (MFPC): No, PMF Required (MFPR): No

4 bytes   50   Extended Supported Rates  30 48 60 6C                                                                    24, 36, 48, 54 Mbit/s
22 bytes  61   HT Operation              06 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00              Primary Channel: 6, HT Channel Width: False, Secondary Channel Offset: 0
6 bytes   150  Cisco                     00 40 96 00 07 00                                                              Parser not implemented. Contact developer if you want this supported.
24        221  Vendor                    00 50 F2 01 01 00 00 50 F2 04 01 00 00 50 F2 04 01 00 00 50 F2 01 00 00        Microsoft
```
