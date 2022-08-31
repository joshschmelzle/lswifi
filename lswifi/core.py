# -*- coding: utf-8 -*-

"""
lswifi.core
~~~~~~~~~~~

code to manage clients (interfaces), their data, and writing out results.
"""

# python imports
import asyncio
import contextlib
import datetime
import json
import logging
import os
import sys
from time import sleep

# app imports
from . import wlanapi as WLAN_API
from .__version__ import __title__
from .client import Client, get_interface_info
from .constants import APNAMEJSONFILE
from .elements import WirelessNetworkBss
from .helpers import (
    Base64Encoder,
    format_bytes_as_hex,
    generate_pretty_separator,
    get_attr_max_len,
    is_five_band,
    is_six_band,
    is_two_four_band,
    remove_control_chars,
    strip_mac_address_format,
)
from .schemas.out import *


def list_interfaces(interfaces) -> None:
    """
    Print interfaces and exit
    """

    print(f"There are {len(interfaces)} interfaces on this system:")
    for interface in interfaces:
        print(
            f"    Description: {interface.description}\n"
            f"    GUID: {interface.guid_string.replace('{', '').replace('}', '').lower()}\n"
            f"    State: {interface.state_string}\n"
        )
    sys.exit()


def watch_events(args, interfaces) -> None:
    """
    Watch for notifications on wireless interfaces
    """
    for interface in interfaces:
        Client(args, interface)

    try:
        while True:
            sleep(5)
    except KeyboardInterrupt:
        pass


async def scan(args, **kwargs):
    """
    async func to perform a scan
    """
    clients = []
    log = logging.getLogger(__name__)
    interfaces = WLAN_API.WLAN.get_wireless_interfaces()

    try:
        if args.list_interfaces:
            list_interfaces(interfaces)

        if args.event_watcher:
            watch_events(args, interfaces)
            sys.exit(0)

        if args.append:
            appendEthers(args.append)
            sys.exit(0)

        if args.display_ethers:
            displayEthers()
            sys.exit(0)

        for interface in interfaces:
            if (
                args.get_interface_info
                or args.get_current_ap
                or args.get_current_channel
                or args.supported
            ):
                print(get_interface_info(args, interface))
                continue
            elif args.bytefile:
                decode_bytefile(args)
                sys.exit(0)
            else:  # TODO: this should be async.
                client = Client(args, interface)
                clients.append(client)
                await client.scan()

        while True:  # can something be futured or awaited?
            if all([i.scan_finished for i in clients]):
                break
            else:
                await asyncio.sleep(0.1)

        for client in clients:
            if client.data is not None:
                log.debug(f"start parsing bss ies for {client.mac}")
                parse_bss_list_and_print(client.data, args, **kwargs)
                log.debug(f"finish parsing bss ies for {client.mac}")
        sys.exit(0)
    except asyncio.CancelledError:
        pass
    except SystemExit as error:
        if error == 0:
            log.error(error)
        else:
            pass


def displayEthers():
    log = logging.getLogger(__name__)
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    is_path = os.path.isdir(appdata_path)
    if not is_path:
        log.info("nothing here")

    file = os.path.join(appdata_path, "ethers")

    try:
        if os.path.isfile(file):
            content = ""
            with open(file, "r") as file_reader:
                content = file_reader.readlines()
            content = [x.strip() for x in content]
            print("\n".join(content))
    except:
        pass


def appendEthers(data):
    log = logging.getLogger(__name__)
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    is_path = os.path.isdir(appdata_path)
    if not is_path:
        os.makedirs(appdata_path)

    file = os.path.join(appdata_path, "ethers")

    ethers = {}
    newethers = {}

    try:
        bssid, apname = data.split(",", 1)

        if not os.path.isfile(file):
            with open(file, "w") as outfile:
                outfile.write(f"{bssid} {apname.strip().replace(' ', '')}\n")
            newethers[bssid] = apname
            return newethers

        if os.path.isfile(file):
            ethers = loadEthers()
            log.debug(f"<storedEthers>: {ethers}")
            if ethers.items():
                for key, value in ethers.items():
                    if bssid in key:
                        newethers[key] = apname
                    else:
                        newethers[bssid] = apname
                        newethers[key] = value
            else:
                newethers[bssid] = apname
            with open(file, "w") as outfile:
                for key, value in newethers.items():
                    outfile.write(f"{key} {value.strip().replace(' ', '')}\n")

            log.debug(f"<newEthers>: {newethers}")
            return newethers
    except ValueError:
        log.error("could not process data (%s) to append to ethers", data)
        return newethers


def loadEthers() -> dict:
    logging.getLogger(__name__)
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    is_path = os.path.isdir(appdata_path)
    if not is_path:
        os.makedirs(appdata_path)

    file = os.path.join(appdata_path, "ethers")
    ethers = {}
    if os.path.isfile(file):
        with open(file, "r") as infile:
            for line in infile:
                mac, name = line.split(" ", 1)
                ethers[mac] = name.strip()

    return ethers


def loadAPNames() -> dict:
    log = logging.getLogger(__name__)
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    is_path = os.path.isdir(appdata_path)
    if not is_path:
        os.makedirs(appdata_path)

    file = os.path.join(appdata_path, APNAMEJSONFILE)
    apnames = {}
    if os.path.isfile(file):
        with open(file, "r") as fp:
            with contextlib.suppress(json.decoder.JSONDecodeError):
                apnames = json.load(fp)

    log = logging.getLogger(__name__)
    log.debug(f"<loadAPNames>: len(json_names) {len(apnames)}")
    return apnames


def updateAPNames(json_names, scan_names) -> None:
    log = logging.getLogger(__name__)
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    is_path = os.path.isdir(appdata_path)
    if not is_path:
        os.makedirs(appdata_path)

    file = os.path.join(appdata_path, "apnames.json")

    # if mac from updated is in current, check if ap name is different or the same.
    # if different, update it.
    # if the same. pass.

    newcount = 0
    for scan_bss, scan_name in scan_names.items():
        if scan_name != "":  # if not ""
            if scan_bss in json_names.keys():  # if name from scan is in the json file
                if (
                    json_names[scan_bss] != scan_name
                ):  # if scan name is different from json name
                    old = json_names[scan_bss]
                    json_names[scan_bss] = scan_name  # update loadednames
                    log.debug(f"<updateAPNames> {old} updated to {scan_name}")
                    newcount += 1
            else:
                json_names[scan_bss] = scan_name
                log.debug(f"<updateAPNames> new value {scan_name} added")
                newcount += 1
    log.debug(
        f"<updateAPNames> len(json_names) {len(json_names)} len(new_names) {len(scan_names)}"
    )
    if newcount > 0:
        {**json_names, **scan_names}
        with open(file, "w") as fp:
            json.dump(json_names, fp)
            log.debug(f"{len(scan_names.items())} new names written to {file}")
    else:
        log.debug("<updateAPNames> nothing to update")


def parse_bss_list_and_print(wireless_network_bss_list, args, **kwargs):
    DISPLAY_SENSITIVITY = -82
    out_results = []
    bssid_list = []

    log = logging.getLogger(__name__)

    if kwargs is not None:
        for key, value in kwargs.items():
            if args.apnames and "stored" in key:
                log.debug(
                    f"has user provided ack for caching AP names on their local machine? ({value})"
                )
                if value:
                    stored_ack = value
                else:
                    stored_ack = value

    if args.ethers:
        ethers = loadEthers()

    if args.apnames:
        if stored_ack:
            json_names = loadAPNames()

    exportpath = None

    if args.export:
        appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
        is_path = os.path.isdir(appdata_path)
        if not is_path:
            os.makedirs(appdata_path)

        datepath = os.path.join(appdata_path, str(datetime.date.today()))
        datepathexists = os.path.isdir(datepath)
        if not datepathexists:
            os.makedirs(datepath)

        exportpath = os.path.join(
            datepath,
            str(datetime.datetime.now().replace(microsecond=0).time()).replace(":", ""),
        )
        log.debug(f"raw byte files exported to {exportpath}")
        if not os.path.isdir(exportpath):
            os.makedirs(exportpath)

        # print(datetime.date.today())
        # print(str(datetime.datetime.now().replace(microsecond=0).time()).replace(":",""))
        # print(datetime.datetime.now().replace(microsecond=0).isoformat().replace(":",""))

    newapnames = {}

    json_out = []

    bss_len = len(wireless_network_bss_list)
    # WirelessNetworkBss object
    for index, bss in enumerate(wireless_network_bss_list):
        if args.ies or args.bytes or args.export:
            wlanapi_bss = str(bss.bssid).lower()  # TODO EXTRACT INTO HELPER

            if args.ies:
                user_bss = args.ies.lower()
            if args.bytes:
                user_bss = args.bytes.lower()

            if args.export:
                if args.export != 4:
                    user_bss = args.export
                    # print(f"{bss_len} {index}")
                    # print(f"{wlanapi_bss} {user_bss}")

                    if wlanapi_bss != user_bss:
                        # print("{} {}".format(wlanapi_bss, user_bss))
                        if bss_len == (index + 1):
                            print(
                                f"no match for {args.export} found in scan results. please try again ..."
                            )
                        continue

                export_bss = str(bss.bssid).lower().replace(":", "-")

                bsspath = export_bss + ".bss"
                # print(f"{os.path.join(exportpath, bss)}")
                # print(f"{type(bss.bssbytes.send())}")
                # print(f"{bss.bssbytes.send()}")
                bssfile = open(os.path.join(exportpath, bsspath), "wb")
                try:
                    bssfile.write(bss.bssbytes.send())
                finally:
                    bssfile.close()

                iespath = export_bss + ".ies"
                # print(f"{os.path.join(exportpath, ies)}")
                # print(f"{type(bss.iesbytes)}")
                # print(f"{bss.iesbytes}")
                iesfile = open(os.path.join(exportpath, iespath), "wb")
                try:
                    iesfile.write(bss.iesbytes)
                finally:
                    iesfile.close()

                # print(f"{bsspath} {iespath}")

                if args.export != 4:
                    print(f"raw byte files for {args.export} exported to {exportpath}")
                    break
                elif bss_len == index:
                    print(f"{bss_len} total raw byte files exported to {exportpath}")

                continue

            # compare if bss from list is the same as the one the user wants details for
            if wlanapi_bss != user_bss:
                # print("{} {}".format(wlanapi_bss, user_bss))
                continue
            if args.ies:
                print(bss)
            if args.bytes:
                print("bss.bssbytes.send():")
                print(f"{bss.bssbytes.send()}\n")
                print("base64 encoded (bss.bssbytes.send()):")
                print(f"{json.dumps(bss.bssbytes.send(), cls=Base64Encoder)}\n")
                print(
                    f"decoded as ISO-8859-1: \n {(bss.bssbytes.send()).decode(encoding='ISO-8859-1')}\n"
                )
                print(f"bss octets:\n{format_bytes_as_hex(bss.bssbytes.send())}\n")
                print(f"ies octets:\n{format_bytes_as_hex(bss.iesbytes)}\n")
            break

        # handle weakest rssi value we want to see displayed to the screen
        if args.sensitivity:
            try:
                DISPLAY_SENSITIVITY = int(args.sensitivity)
                if DISPLAY_SENSITIVITY not in range(-100, -1):
                    print("rssi threshold must be between -1 and -100... exiting...")
                    sys.exit(-1)
            except ValueError:
                print(f"{args.sensitivity} not a valid threshold... exiting...")
                sys.exit(-1)
        if bss.rssi.value < DISPLAY_SENSITIVITY:
            continue

        # handle band filters
        if not args.a and not args.g and not args.six:
            pass
        else:
            # handle a band filter
            if args.a and args.g and not args.six:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    pass
                if is_five_band(int(bss.channel_frequency.value)):
                    pass
                if is_six_band(int(bss.channel_frequency.value)):
                    continue
            if args.a and args.six and not args.g:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    continue
                if is_five_band(int(bss.channel_frequency.value)):
                    pass
                if is_six_band(int(bss.channel_frequency.value)):
                    pass
            if args.a and not args.six and not args.g:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    continue
                if is_five_band(int(bss.channel_frequency.value)):
                    pass
                if is_six_band(int(bss.channel_frequency.value)):
                    continue
            # handle g band filter
            if args.g and args.six and not args.a:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    pass
                if is_five_band(int(bss.channel_frequency.value)):
                    continue
                if is_six_band(int(bss.channel_frequency.value)):
                    pass
            if args.g and not args.six and not args.a:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    pass
                if is_five_band(int(bss.channel_frequency.value)):
                    continue
                if is_six_band(int(bss.channel_frequency.value)):
                    continue
            # handle six band filter
            if args.six and not args.a and not args.g:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    continue
                if is_five_band(int(bss.channel_frequency.value)):
                    continue
                if is_six_band(int(bss.channel_frequency.value)):
                    pass

        # handle width filter
        valid_channels = ["20", "40", "80", "160"]
        if args.width is not None:
            if args.width not in valid_channels:
                print(
                    f"channel width {args.width} not valid. must use one of these values: {', '.join(valid_channels)}"
                )
                sys.exit(-1)
            if args.width not in str(bss.channel_width):
                continue

        # handle hidden ssid, and handle ssid filter
        if args.include is None:
            pass
        elif args.include in str(bss.ssid):
            pass
        else:
            continue

        # handle exclude filter
        if args.exclude:
            if args.exclude in str(bss.ssid):
                continue

        # directed scan on BSSID or OUI
        if args.bssid is not None:
            input_mac = strip_mac_address_format(args.bssid)
            bss_mac = strip_mac_address_format(str(bss.bssid))
        # print("{} {}".format(input_mac, bss_mac))
        if args.bssid is None:
            pass
        elif input_mac in bss_mac:
            pass
        else:
            continue

        # this is a list to check for dup bssids (may be expected for some APs which share same BSSID on 2.4 and 5 GHz radios - Cisco for example)
        bssid_list.append(str(bss.bssid))

        if args.ethers:
            if bss.bssid.value in ethers:
                bss.apname.value = ethers[bss.bssid.value]
        elif args.apnames:
            if stored_ack:
                scan_bssid = bss.bssid.value
                scan_apname = remove_control_chars(bss.apname.value)

                if json_names.get(scan_bssid) is not None:  # if bssid is in json dict
                    cachedAP = json_names[scan_bssid]
                    bss.apname.value = cachedAP  # start with cached
                    if scan_apname != "":  # if current AP name is not an empty string
                        if (
                            scan_apname != cachedAP
                        ):  # if current AP doesn't match whats in the json
                            newapnames[
                                scan_bssid
                            ] = scan_apname  # then 1) update new hash table with current AP name
                            bss.apname.value = scan_apname  # then 2) update the apname that will be displayed
                    log.debug(
                        f"LIVE BSSID {scan_bssid} CACHED {cachedAP} SCANNED {scan_apname}"
                    )
                elif scan_apname != "":  # working with new AP name
                    newapnames[
                        scan_bssid
                    ] = scan_apname  # then 1) update new hash table with new AP name

        # bss.element.out() contains a tuple with the following values
        #   1. value, 2. header and alignment (left, center, right), 3. subheader

        connected = False
        if bss.bssid.connected:
            connected = True
            if not args.json:
                bss.bssid.value += "(*)"

        json_out.append(
            {
                "amendments": sorted(bss.amendments.elements),
                "apname": str(bss.apname).strip(),
                "bssid": str(bss.bssid).strip(),
                "bss_type=": str(bss.bss_type).strip(),
                "channel_frequency": str(bss.channel_frequency).strip(),
                "channel_number": str(bss.channel_number).strip(),
                "channel_width": str(bss.channel_width).strip(),
                "connected": connected,
                "ies": sorted(bss.ie_numbers.elements),
                "ies_extension": sorted(bss.exie_numbers.elements),
                "modes": sorted(bss.modes.elements),
                "phy_type": str(bss.phy_type).strip(),
                "rates_basic": [x for x in bss.wlanrateset.basic.split(" ")],
                "rates_data": [x for x in bss.wlanrateset.data.split(" ")],
                "rssi": str(bss.rssi),
                "security": str(bss.security).strip(),
                "pmf": str(bss.pmf).strip(),
                "spatial_streams": str(bss.spatial_streams),
                "ssid": str(bss.ssid).strip(),
                "stations": str(bss.stations),
                "uptime": str(bss.uptime).strip(),
                "utilization": str(bss.utilization).strip(),
            }
        )

        if args.pmf:
            out_results.append(
                [
                    bss.ssid.out(),
                    bss.bssid.out(),
                    bss.rssi.out(),
                    bss.phy_type.out(),
                    bss.channel_number_marked.out(),
                    bss.channel_frequency.out(),
                    bss.spatial_streams.out(),
                    bss.security.out(),
                    bss.amendments.out(),
                    bss.pmf.out(),
                    bss.uptime.out(),
                ]
            )
        else:
            out_results.append(
                [
                    bss.ssid.out(),
                    bss.bssid.out(),
                    bss.rssi.out(),
                    bss.phy_type.out(),
                    bss.channel_number_marked.out(),
                    bss.channel_frequency.out(),
                    bss.spatial_streams.out(),
                    bss.security.out(),
                    bss.amendments.out(),
                    bss.uptime.out(),
                ]
            )

        if args.interval:
            out_results[-1].append(bss.beacon_interval.out())

        if args.tpc:
            out_results[-1].append(bss.transmit_power.out())

        if args.qbss:
            out_results[-1].append(bss.stations.out())
            out_results[-1].append(bss.utilization.out())

        if args.apnames or args.ethers:
            out_results[-1].append(bss.apname.out())

    def get_index(key):
        for r in out_results:
            for i, x in enumerate(r):
                if key in str(x.header):
                    return i
        return -1

    if args.uptime:  # sort by uptime
        out_results = sorted(
            out_results,
            key=lambda x: int(x[get_index("UPTIME")].value.split("d")[0]),
            reverse=False,
        )
    else:  # sort by RSSI
        out_results = sorted(
            out_results, key=lambda x: x[get_index("RSSI")].value, reverse=False
        )

    # here because i added the verbose, byte file func and export func to this func
    if args.ies or args.bytes or args.export:
        return

    # outlist to screen
    log.info(
        f"display filter sensitivity {DISPLAY_SENSITIVITY}; "
        f"output includes {len(out_results)} of {len(wireless_network_bss_list)} BSSIDs detected in scan results."
    )

    if len(out_results) > 0:

        connected = False
        headers = []
        subheaders = []

        # check for substring that indicates the scanning interface is also connected to a BSSID found in results
        for row in out_results:
            for data in row:
                if "(*)" in str(data):
                    connected = True

        for tup in out_results[0]:
            headers.append(tup.header)

        for tup in out_results[0]:
            if "BSSID" in tup.header.value:
                if connected:
                    tup.subheader = SubHeader("(*): connected")
            subheaders.append(tup.subheader)

        # define fun ascii border
        header_decorators = ["~", "+", "="]
        begin_upper = "-"
        end_upper = "-"
        out_header_decorators = ()

        subheader_decorators = ["+", "~", "="]
        begin_lower = "-"
        end_lower = "-"
        out_subheader_decorators = ()

        result = ""

        # add column header and subheader
        out_results.insert(0, headers)
        out_results.insert(1, subheaders)

        # generate fun ascii border
        for index, item in enumerate(out_results[0]):
            max_len = max(len(x) for x in [y[index] for y in out_results])
            out_header_decorators = out_header_decorators + (
                generate_pretty_separator(
                    max_len, header_decorators, begin_upper, end_upper
                ),
            )
            out_subheader_decorators = out_subheader_decorators + (
                generate_pretty_separator(
                    max_len, subheader_decorators, begin_lower, end_lower
                ),
            )

            arg = [y[index] for y in out_results][0].alignment.value
            result += f"{{{index}:{arg}{max_len}}}  "

        # add fun ascii border
        out_results.insert(0, out_header_decorators)
        out_results.insert(3, out_subheader_decorators)

        # print results
        if not args.json:
            for row in out_results:
                out_results = []
                for data in row:
                    if isinstance(data, OUT_TUPLE):
                        out_results.append(f"{data.value}")
                    else:
                        out_results.append(f"{data}")
                print(result.format(*tuple(out_results)))
        else:
            print(json.dumps(json_out))

    duplicates = set([x for x in bssid_list if bssid_list.count(x) > 1])
    if duplicates:
        log.warning("***BSSIDS WITH DUPLICATE MACs***")
        log.warning(duplicates)
        log.warning("***BSSIDS WITH DUPLICATE MACs***")

    if args.apnames:
        if stored_ack:
            updateAPNames(json_names, newapnames)


def decode_bytefile(args):
    if os.path.isfile(args.bytefile):
        if args.bytefile.lower().rsplit(".", 1)[1] == "ies":
            fh = open(args.bytefile, "rb")
            ies = ""
            try:
                _bytearray = bytearray(fh.read())
                print(
                    f"Raw Information Elements ({len(_bytearray)} "
                    f"bytes):\n{format_bytes_as_hex(_bytearray)}"
                )

                print("")
                ies = WirelessNetworkBss.decode_bytefile_ies(_bytearray)
            finally:
                fh.close()

            out = "Decoded Information Elements:\n"

            length_len = get_attr_max_len(ies, "length")
            id_len = get_attr_max_len(ies, "eid")
            names_len = get_attr_max_len(ies, "name")
            decoded_len = get_attr_max_len(ies, "decoded")
            get_attr_max_len(ies, "pbody")

            out += "{0:<{length_len}}  {1:<{id_len}}  {2:<{names_len}}  {3:<{decoded_len}}  {4:<1}\n".format(
                "Length",
                "ID",
                "Information Element",
                "Decoded",
                "Data",
                length_len=length_len,
                id_len=id_len,
                names_len=names_len,
                decoded_len=decoded_len,
            )

            for ie in ies:
                # if ie.element_id != 11:
                #    continue
                # Length, ID, Information Elements, Parsed, Details

                # _hex = ""
                # for _decimal in ie.body:
                #    _hex = _hex + "{:02x} ".format(_decimal)
                # _hex = _hex + "{}".format(hex(_decimal)[2:])
                out += "{0:<{length_len}}  {1:<{id_len}}  {2:<{names_len}}  {3:<{decoded_len}}  {4:<1}\n".format(
                    ie.length,
                    ie.eid,
                    ie.name,
                    ie.decoded,
                    ie.pbody,
                    length_len=length_len,
                    id_len=id_len,
                    names_len=names_len,
                    decoded_len=decoded_len,
                )
            print(out)
            return

        if args.bytefile.lower().rsplit(".", 1)[1] == "bss":
            fh = open(args.bytefile, "rb")
            ies = ""
            try:
                _bytearray = bytearray(fh.read())
                print(
                    f"Raw BSS ({len(_bytearray)} bytes):\n{format_bytes_as_hex(_bytearray)}"
                )
                print("")
                print(
                    "Decoded BSS Information (NOTE: this is missing information found in .ies file):"
                )
                bss_entry = WLAN_API.WLANBSSEntry.from_buffer(_bytearray)
                data = WirelessNetworkBss(bss_entry, is_byte_file=True)
                print(data)
            finally:
                fh.close()
    else:
        print(f"{args.bytefile} file does not exist on file system... exiting...")
