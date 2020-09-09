# -*- coding: utf-8 -*-

"""
lswifi.core
~~~~~~~~~~~~~

manager side code for managing clients, their data, and writing to screen?
"""

# python imports
import asyncio
import contextlib
import logging
import os
import pprint
import sys

# app imports
from . import wlanapi as WLAN_API
from .client import Client
from .helpers import (
    is_two_four_band,
    is_five_band,
    strip_mac_address_format,
    generate_pretty_separator,
    Header,
    SubHeader,
    Alignment,
    format_bytes_as_hex,
    get_attr_max_len,
    OUT_TUPLE,
)
from .constants import APNAMEACKFILE, APNAMEJSONFILE
from .elements import WirelessNetworkBss


# def start(args):
#     # TODO: do i still need all this extra asyncio stuff? i'm not supporting <3.7
#     # TODO: and actually...
#     # TODO: why the fuck is the async code here? and not spawning clients?
#     # TODO: it doesn't make sense to be here. WTF am i doing?
#
#     loop = asyncio.new_event_loop()
#     try:
#         sys.exit(loop.run_until_complete(main(args)))
#     except KeyboardInterrupt:
#         # optional message for if the shutdown takes a while
#         print(
#            "caught KeyboardInterrupt... stopping...", flush=True
#         )  # TODO: this needs to be a debug output. silent normally.
#
#         # don't print `asyncio.CancelledError` exceptions during shutdown
#         def shutdown_exception_handler(loop, context):
#            if "exception" not in context or not isinstance(
#                context["exception"], asyncio.CancelledError
#            ):
#                loop.default_exception_handler(context)
#
#         loop.set_exception_handler(shutdown_exception_handler)
#
#         # attempt to shutdown gracefully and wait for tasks to be cancelled
#         tasks = asyncio.gather(
#            *asyncio.all_tasks(loop=loop), loop=loop, return_exceptions=True
#         )
#         tasks.add_done_callback(lambda t: loop.stop())
#         tasks.cancel()
#
#         # keep event loop running until it's either destroyed or tasks have terminated
#         while not tasks.done() and not loop.is_closed():
#            loop.run_forever()
#     finally:
#         loop.close()


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
    from time import sleep

    for interface in interfaces:
        Client(args, interface).watch()
    try:
        while True:
            sleep(5)
    except KeyboardInterrupt:
        pass


async def scan(args, **kwargs):
    # init scan
    clients = []
    log = logging.getLogger(__name__)
    interfaces = WLAN_API.WLAN.get_wireless_interfaces()

    try:
        if args.list_interfaces:
            list_interfaces(interfaces)

        if args.event_watcher:
            watch_events(args, interfaces)

        for interface in interfaces:
            if (
                args.get_interface_info
                or args.get_current_ap
                or args.get_current_channel
                or args.supported
            ):
                get_interface_info(args, interface)
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
                log.debug(f"start parsing bss ies")
                parse_bss_list_and_print(client.data, args, **kwargs)
                log.debug(f"finish parsing bss ies")
        sys.exit(0)
    except asyncio.CancelledError:
        pass
    except SystemExit as error:
        if error == 0:
            log.error(error)
        else:
            pass


from struct import *


def appendEthers(data) -> None:
    import __main__ as main

    log = logging.getLogger(__name__)
    name = str(main.__file__).rsplit("\\", 1)[1].split(".")[0]
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), name)
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        os.makedirs(parentexportpath)

    file = os.path.join(parentexportpath, "ethers")

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
        print(f"could not process data ({data}) to append to ethers")
        return newethers


def loadEthers() -> []:
    import __main__ as main

    name = str(main.__file__).rsplit("\\", 1)[1].split(".")[0]
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), name)
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        os.makedirs(parentexportpath)

    file = os.path.join(parentexportpath, "ethers")
    ethers = {}
    if os.path.isfile(file):
        with open(file, "r") as infile:
            for line in infile:
                mac, name = line.split(" ", 1)
                ethers[mac] = name.strip()

    return ethers


import json


def loadAPNames() -> {}:
    import __main__ as main

    name = str(main.__file__).rsplit("\\", 1)[1].split(".")[0]
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), name)
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        os.makedirs(parentexportpath)

    file = os.path.join(parentexportpath, APNAMEJSONFILE)
    apnames = {}
    if os.path.isfile(file):
        with open(file, "r") as fp:
            with contextlib.suppress(json.decoder.JSONDecodeError):
                apnames = json.load(fp)

        #    for line in infile:
        #        try:
        #            mac, name = line.split(' ', 1)
        #            apnames[mac] = name.strip()
        #        except:
        #            pass

    log = logging.getLogger(__name__)
    log.debug(f"<loadAPNames>: len(json_names) {len(apnames)}")
    return apnames


def updateAPNames(json_names, scan_names) -> None:
    import __main__ as main

    log = logging.getLogger(__name__)
    name = str(main.__file__).rsplit("\\", 1)[1].split(".")[0]
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), name)
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        log.debug(os.makedirs(parentexportpath))
    file = os.path.join(parentexportpath, "apnames.json")

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
        out = {**json_names, **scan_names}
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

    if args.append:
        ethers = appendEthers(args.append)
        sys.exit(0)
    if args.ethers:
        ethers = loadEthers()

    if args.apnames:
        if stored_ack:
            json_names = loadAPNames()

    exportpath = None

    if args.export:
        import __main__ as main

        name = str(main.__file__).rsplit("\\", 1)[1].split(".")[0]
        parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), name)
        parentexportpathexists = os.path.isdir(parentexportpath)
        if not parentexportpathexists:
            os.makedirs(parentexportpath)

        import datetime

        datepath = os.path.join(parentexportpath, str(datetime.date.today()))
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

    bsslen = len(wireless_network_bss_list)
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
                    # print(f"{bsslen} {index}")
                    # print(f"{wlanapi_bss} {user_bss}")

                    if wlanapi_bss != user_bss:
                        # print("{} {}".format(wlanapi_bss, user_bss))
                        if bsslen == index:
                            print(f"no match for {args.export} found in scan results")
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
                    print(f"raw byte file for {args.export} exported to {exportpath}")
                    break
                elif bsslen == index:
                    print(f"{bsslen} total raw byte files exported to {exportpath}")

                continue

            # compare if bss from list is the same as the one the user wants details for
            if wlanapi_bss != user_bss:
                # print("{} {}".format(wlanapi_bss, user_bss))
                continue
            if args.ies:
                print(bss)
            if args.bytes:
                # print(f"bss bytes:\n{bss.bssbytes.send()}\n")
                print(f"type(bss.bssbytes.send(): {type(bss.bssbytes.send())}")
                print(f"{bss.bssbytes.send()}")
                print(
                    f"unicode_escape: \n {(bss.bssbytes.send()).decode(encoding='unicode_escape')}\n"
                )
                print(f"bss bytes:\n{format_bytes_as_hex(bss.bssbytes.send())}\n")
                # print(f"bss bytes:\n{type(bss.bssbytes.send())}\n")
                # print(f"ies bytes:\n{bss.iesbytes}\n")
                print(f"ies bytes:\n{format_bytes_as_hex(bss.iesbytes)}\n")
                # print(f"ies bytes:\n{type(bss.iesbytes)}\n")

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
        if args.a and args.g:
            pass
        else:
            if args.g:
                if is_two_four_band(int(bss.channel_frequency.value)):
                    pass
                else:
                    continue
            if args.a:
                if is_five_band(int(bss.channel_frequency.value)):
                    pass
                else:
                    continue

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

        # this is a list to check for dup bssids
        bssid_list.append(str(bss.bssid))

        if args.ethers:
            if bss.bssid.value in ethers:
                bss.apname.value = ethers[bss.bssid.value]
        elif args.apnames:
            if stored_ack:
                scan_bssid = bss.bssid.value
                scan_apname = bss.apname.value

                if json_names.get(scan_bssid) is not None:  # if bssid is in json dict
                    cachedAP = json_names[scan_bssid]
                    bss.apname.value = cachedAP  # start with cached
                    if scan_apname != "":  # if current AP name is not an empty string
                        if (
                            scan_apname != cachedAP
                        ):  # if current AP doesn't match whats in the json
                            newapnames[
                                scan_bssid
                            ] = (
                                scan_apname
                            )  # then 1) update new hash table with current AP name
                            bss.apname.value = (
                                scan_apname
                            )  # then 2) update the apname that will be displayed
                    log.debug(
                        f"LIVE BSSID {scan_bssid} CACHED {cachedAP} SCANNED {scan_apname}"
                    )
                elif scan_apname != "":  # working with new AP name
                    newapnames[
                        scan_bssid
                    ] = scan_apname  # then 1) update new hash table with new AP name

        # bss.element.out() contains a tuple with the following values
        #   1. value, 2. header and alignment (left, center, right), 3. subheader

        if bss.bssid.connected:
            bss.bssid.value += "(*)"

        if args.apnames or args.ethers:
            out_results.append(
                [
                    bss.ssid.out(),
                    bss.bssid.out(),
                    bss.apname.out(),
                    bss.rssi.out(),
                    bss.phy_type.out(),
                    bss.channel_number_marked.out(),
                    # bss.channel_width.out(),
                    bss.spatial_streams.out(),
                    # bss.security.out(),
                    bss.amendments.out(),
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
                    # bss.channel_width.out(),
                    bss.spatial_streams.out(),
                    bss.security.out(),
                    bss.amendments.out(),
                    bss.uptime.out(),
                    # bss.ienumbers.out(),
                ]
            )

    if args.uptime:  # sort by uptime
        out_results = sorted(
            out_results, key=lambda x: int(x[8].value.split("d")[0]), reverse=False
        )
    elif args.apnames or args.ethers:  # sort by RSSI
        out_results = sorted(out_results, key=lambda x: x[3].value, reverse=False)
    else:
        out_results = sorted(out_results, key=lambda x: x[2].value, reverse=False)

    # here because i added the verbose, byte file func and export func to this func
    if args.ies or args.bytes or args.export:
        return

    # outlist to screen
    print(
        f"display filter sensitivity {DISPLAY_SENSITIVITY}; "
        f"displaying {len(out_results)} of {len(wireless_network_bss_list)} BSSIDs detected in scan results:"
    )

    if len(out_results) > 0:

        connected = False
        headers = []
        subheaders = []

        # check for substring that indicates interface is connected to a BSSID in results
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
        for row in out_results:
            out_results = []
            for data in row:
                if isinstance(data, OUT_TUPLE):
                    out_results.append(f"{data.value}")
                else:
                    out_results.append(f"{data}")
            print(result.format(*tuple(out_results)))

    # TODO: needs a test to verify this actually does what it should. ALERT the user of dup MACs
    duplicates = set([x for x in bssid_list if bssid_list.count(x) > 1])
    if duplicates:
        print("***DUPLICATE MACS***")
        print(duplicates)
        print("***DUPLICATE MACS***")

    if args.apnames:
        if stored_ack:
            updateAPNames(json_names, newapnames)


def get_interface_info(args, iface):
    outstr = ""
    interface_info = {}
    connected = True

    if "disconnected" in iface.state_string:
        connected = False

    if not args.get_current_channel and not args.get_current_ap:
        if connected:
            outstr += f"Interface: {iface.description} is connected\n"
        else:
            outstr += f"Interface: {iface.description} is disconnected\n"

    # query interface for supported info
    params = ["current_connection", "channel_number", "statistics", "rssi"]
    for p in params:
        result = WLAN_API.WLAN.query_interface(iface, p)
        interface_info[p] = result

        if args.supported:
            if isinstance(result, tuple):
                outstr += f"    {p}: {pprint.pformat(result, indent=4)}\n"
            else:
                outstr += f"    {p}: {result}\n"

    if connected and not args.supported:
        # print(interface_info.items())
        bssid = ""
        for key, result in interface_info.items():
            if key == "current_connection":
                connected_ssid = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11Ssid",
                )
                bssid = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11Bssid",
                )
                dot11PhyType = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11PhyType",
                )
                wlanSignalQuality = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="wlanSignalQuality",
                )
                ulRxRate = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="ulRxRate",
                )
                ulTxRate = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="ulTxRate",
                )
                dot11BssType = parse_result(
                    result=result[1],
                    data_type="wlanAssociationAttributes",
                    data="dot11BssType",
                )
                state = parse_result(result=result[1], data_type="isState")
                wlanConnectionMode = parse_result(
                    result=result[1], data_type="wlanConnectionMode"
                )
                strProfileName = parse_result(
                    result=result[1], data_type="strProfileName"
                )
                SecurityEnabled = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="bSecurityEnabled",
                )
                oneXEnabled = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="bOneXEnabled",
                )
                dot11AuthAlgorithm = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="dot11AuthAlgorithm",
                )
                dot11CipherAlgorithm = parse_result(
                    result=result[1],
                    data_type="wlanSecurityAttributes",
                    data="dot11CipherAlgorithm",
                )

                outstr += f"    Description: {iface.description}\n"
                outstr += (
                    f"    GUID: {iface.guid_string.strip('{').strip('}').lower()}\n"
                )
                outstr += f"    State: {state}\n"
                if "wlan_connection_mode_" in wlanConnectionMode:
                    wlanConnectionMode = wlanConnectionMode[21:]
                outstr += (
                    f"    Connection Mode: {wlanConnectionMode}\n"
                    f"    Profile Name: {strProfileName}\n"
                )
                outstr += f"    SSID: {bytes.decode(connected_ssid)}\n"
                outstr += f"    BSSID: {bssid}\n"
                outstr += f"    BSS Type: {dot11BssType}\n"
                outstr += f"    PHY: {dot11PhyType}\n"
                # out += "PH    Y Index: {}\n".format(uDot11PhyIndex)
                outstr += f"    Signal Quality: {wlanSignalQuality}%\n"
                outstr += f"    Rx Rate: {ulRxRate/1000} Mbps\n"
                outstr += f"    Tx Rate: {ulTxRate/1000} Mbps\n"
                outstr += (
                    f"    Security: {'Enabled' if SecurityEnabled else 'Disabled'}\n"
                )
                outstr += f"    .1X: {'Enabled' if oneXEnabled else 'Disabled'}\n"
                outstr += f"    Authentication: {dot11AuthAlgorithm}\n"
                outstr += f"    Cipher: {dot11CipherAlgorithm}\n"

            if "ERROR_NOT_SUPPORTED" in result:
                pass

            if "failed" not in result:
                if key == "channel_number":
                    channel = result[0].value

                    outstr += "    Channel: {}\n".format(channel)

                    if args.get_current_ap and args.get_current_channel:
                        if args.raw and args.json:
                            print(f'{{"bssid":"{bssid}","channel":"{channel}"}}')
                            return
                        elif args.raw:
                            print(f"{bssid}, {channel}")
                            return
                        else:
                            print(
                                f"Interface: {iface.description}, BSSID: {bssid}, CHANNEL: {channel}"
                            )
                            return

                    if args.get_current_ap:
                        if args.raw:
                            print(bssid)
                            return
                        else:
                            print(f"Interface: {iface.description}, BSSID: {bssid}")
                            return

                    if args.get_current_channel:
                        if args.raw:
                            print(channel)
                            return
                        else:
                            print(f"Interface: {iface.description}, Channel: {channel}")
                            return

    print(outstr)


def decode_bytefile(args):
    print(args.bytefile)
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
            pbody_len = get_attr_max_len(ies, "pbody")

            out += "{0:<{length_len}}  {1:<{id_len}}  {2:<{names_len}}  {3:<{decoded_len}}  {4:<1}\n".format(
                "Length",
                "ID",
                "Information Element",
                "Decoded",
                "Data",
                length_len=length_len,
                id_len=id_len,
                names_len=names_len,
                pbody_len=pbody_len,
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
                    pbody_len=pbody_len,
                    decoded_len=decoded_len,
                )
            print(out)
            return

        if args.bytefile.lower().rsplit(".", 1)[1] == "bss":
            print("############################")
            print("## TODO: not finished yet ##")
            print("############################")
            fh = open(args.bytefile, "rb")
            ies = ""
            try:
                _bytearray = bytearray(fh.read())
                print(
                    "Raw BSS ({len(_bytearray)} bytes):\n{format_bytes_as_hex(_bytearray)}"
                )
                print("")

                # TODO: incomplete...
                bssEntry = WLAN_API.WLANBSSEntry()
                fh.readinto(bssEntry)  # THIS DOES NOT WORK!!! LOL

            finally:
                fh.close()
    else:
        print(f"{args.winfi} file does not exist on file system... exiting...")


def parse_result(result, data_type, **kwargs):
    data = kwargs.get("data", None)
    try:
        if data:
            return result[data_type][data]
        else:
            return result[data_type]
    except KeyError:
        if data:
            return f"unknown {data}"
        else:
            return f"unknown {data_type}"
