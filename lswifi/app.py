# -*- coding: utf-8 -*-
#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

"""
lswifi.core
~~~~~~~~~~~

code to manage clients (interfaces), their data, and writing out results.
"""

# python imports
import asyncio
import concurrent.futures
import contextlib
import csv
import datetime
import json
import logging
import os
import struct
import sys
import time
import traceback
from ctypes import POINTER, cast, create_string_buffer
from operator import itemgetter
from time import sleep

# app imports
from lswifi import wlanapi as WLAN_API
from lswifi.__version__ import __title__, __version__
from lswifi.client import Client, get_interface_info
from lswifi.constants import APNAMEJSONFILE, DECORS, DECORS_END, DECORS_START
from lswifi.elements import WirelessNetworkBss
from lswifi.helpers import (
    Base64Encoder,
    format_bytes_as_hex,
    generate_pretty_separator,
    get_attr_max_len,
    get_index,
    is_five_band,
    is_six_band,
    is_two_four_band,
    remove_control_chars,
    strip_mac_address_format,
)
from lswifi.pcapng import PCAPNG
from lswifi.schemas.out import *


class lswifi:
    def run(self, args, **kwargs):
        log = logging.getLogger(__name__)
        loops_completed = 0
        is_caching_acknowledged = False

        if kwargs is not None:
            for key, value in kwargs.items():
                if args.apnames and "stored" in key:
                    log.debug(
                        f"has user provided ack for caching AP names on their local machine? {'Yes' if value else 'No'}"
                    )
                    if value:
                        is_caching_acknowledged = value

        watching_events = True
        try:
            clients = {}
            try:
                if args.event_watcher:
                    while watching_events:
                        for (
                            index,
                            iface,
                        ) in WLAN_API.WLAN.get_wireless_interfaces().items():
                            if "disabled" not in iface.mac:
                                if iface.mac not in clients.keys():
                                    client = Client(args, iface)
                                    clients[iface.mac] = client
                        sleep(2)

                for index, iface in WLAN_API.WLAN.get_wireless_interfaces().items():
                    clients[index] = Client(args, iface)
            except Exception as error:
                log.error("%s" % error)

            if len(clients) == 0:
                log.error(f"no wireless interfaces found")
                sys.exit(-1)

            if args.list_interfaces:
                print(f"There are {len(clients)} interfaces on this system:")
                for _index, client in clients.items():
                    print(
                        f"    Connection Name: {client.iface.connection_name}\n"
                        f"    Description: {client.iface.description}\n"
                        f"    GUID: {client.iface.guid_string.replace('{', '').replace('}', '').lower()}\n"
                        f"    MAC: {client.iface.mac}\n"
                        f"    State: {client.iface.state_string}\n"
                    )
                sys.exit(0)

            if args.append:
                self.appendEthers(args.append)
                sys.exit(0)

            if args.display_ethers:
                self.displayEthers()
                sys.exit(0)

            if args.decoderaw:
                self.decode_bytefile(args)
                sys.exit(0)

            if args.decode:
                self.decode_pcapng_file(args)
                sys.exit(0)

            scanning = True

            # for _index, interface in interfaces.items():
            #     if (
            #         args.get_interface_info
            #         or args.get_current_ap
            #         or args.get_current_channel
            #         or args.supported
            #     ):
            #         scanning = False
            #         print(get_interface_info(args, interface))
            for _index, client in clients.items():
                if (
                    args.get_interface_info
                    or args.get_current_ap
                    or args.get_current_channel
                    or args.supported
                ):
                    scanning = False
                    print(get_interface_info(args, client.iface))

            # TODO move other non-scanning functions here

            if scanning:
                scans = 1
                interval = 0.1
                timeout = 0
                if args.interval:
                    interval = int(args.interval)
                    log.debug(f"interval between scans is {interval}")
                if args.scans:
                    scans = int(args.scans)
                    log.debug(f"number of scans requested is {scans}")
                if args.time:
                    timeout = int(args.time)
                    log.debug(
                        f"duration of time for recurring scans is {timeout} seconds"
                    )

                csv_file_name = ""
                json_file_name = ""
                if args.csv or args.json:
                    csv_file_name = args.csv
                    json_file_name = args.json

                if timeout > 0:  # we're scanning during a given time period
                    timeout_start = time.time()

                    while time.time() < timeout_start + timeout:
                        asyncio.run(
                            self.scan(
                                clients,
                                is_caching_acknowledged,
                                csv_file_name,
                                json_file_name,
                                args,
                            )
                        )
                        loops_completed += 1
                        time.sleep(interval)
                else:  # we're scanning a given number of times
                    _first = True
                    for _index in range(scans):
                        if _first:
                            _first = False
                        else:
                            time.sleep(interval)
                        asyncio.run(
                            self.scan(
                                clients,
                                is_caching_acknowledged,
                                csv_file_name,
                                json_file_name,
                                args,
                            )
                        )
                        loops_completed += 1

                if loops_completed > 1:
                    log.info(f"total number of completed scans is {loops_completed}")
        except KeyboardInterrupt:
            if not args.event_watcher:
                if loops_completed > 1:
                    log.info(
                        f"total number of completed scans during this session is {loops_completed}"
                    )
            log.warning("keyboard interruption detected... stopping...")
            sys.exit(-1)
        except asyncio.CancelledError:
            raise
        except SystemExit as error:
            if error == 0:
                log.error(error)
            else:
                pass

        sys.exit(0)

    async def scan(
        self, clients, is_caching_acknowledged, csv_file_name, json_file_name, args
    ):
        """
        async func to perform a scan
        """
        log = logging.getLogger(__name__)
        try:
            background_tasks = set()
            iface_count = len(clients)
            if iface_count > 1:
                log.info(f"starting scans on {iface_count} interfaces")

            async def scanfunc(index, client):
                log.debug(
                    f"initializing scan on {client.iface.description} {client.iface.guid_string}"
                )
                await client.scan()
                log.debug(
                    f"initialized scan on {client.iface.description} {client.iface.guid_string}"
                )
                try:
                    while not client.scan_finished:
                        time.sleep(0.1)
                except Exception:
                    raise
                clients[index] = client

            for _index, client in clients.items():
                task = scanfunc(_index, client)
                background_tasks.add(task)
                log.debug(f"added background task for {client}")

            if len(clients.items()) > 0:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=len(clients.items())
                ) as executor:
                    futures = []
                    for task in background_tasks:
                        futures.append(executor.submit(asyncio.run, task))
                    for _future in concurrent.futures.as_completed(futures):
                        pass
            clients = {
                k: clients[k] for k in sorted(clients)
            }  # sort by key (index) numerically
            for _idx, client in clients.items():
                if client.data is None:
                    log.warning(f"no scan data for {client.mac}")
                else:
                    (
                        out_results,
                        rnr_results,
                        bss_len,
                        bssid_list,
                        json_names,
                        json_out,
                        newapnames,
                    ) = self.parse_bss_list(
                        client,
                        is_caching_acknowledged,
                        csv_file_name,
                        json_file_name,
                        args,
                    )

                    if args.ies or args.bytes or args.export:
                        return
                    if args.rnr:
                        self.print_rnr_list(rnr_results, client.mac, args)
                    else:
                        self.print_bss_list(
                            out_results,
                            bss_len,
                            client.mac,
                            bssid_list,
                            is_caching_acknowledged,
                            json_names,
                            json_out,
                            newapnames,
                            args,
                        )
                    log.debug(f"finish parsing information elements for {client.mac}")

            ############################
            # old sync example working #
            ############################
            #
            # for _index, interface in interfaces.items():
            #     client = Client(args, interface)
            #     clients[_index] = client
            #     log.debug(
            #         f"initializing scan on {client.iface.description} {client.iface.guid_string}"
            #     )
            #     await client.scan()
            #     log.debug(
            #         f"initialized scan on {client.iface.description} {client.iface.guid_string}"
            #     )
            #     while not client.scan_finished:
            #         pass
            #     if client.data is None:
            #         log.debug(f"no scan data for {client.mac}")
            #     else:
            #         log.debug(f"start parsing bss ies for {client.mac}")
            #         parse_bss_list_and_print(client.data, client, args, **kwargs)
            #         log.debug(f"finish parsing bss ies for {client.mac}")

        except KeyboardInterrupt:
            raise

    def displayEthers(self):
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
        except Exception:
            pass

    def appendEthers(self, data):
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
                ethers = self.loadEthers()
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

    def loadEthers(self) -> dict:
        appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)  # type: ignore
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

    def loadAPNames(self) -> dict:
        log = logging.getLogger(__name__)
        appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)  # type: ignore
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

    def updateAPNames(self, json_names, scan_names) -> None:
        log = logging.getLogger(__name__)
        appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)  # type: ignore
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
                if (
                    scan_bss in json_names.keys()
                ):  # if name from scan is in the json file
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

    def parse_bss_list(
        self, client, is_caching_acknowledged, csv_file_name, json_file_name, args
    ):
        rnr_results = []
        out_results = []
        bssid_list = []
        csv_out = []
        json_out = []

        wireless_network_bss_list = client.data

        log = logging.getLogger(__name__)

        if args.ethers:
            ethers = self.loadEthers()

        json_names = {}

        if is_caching_acknowledged:
            json_names = self.loadAPNames()

        exportpath = None
        exportraw_path = None
        pcapng_path = None

        if args.exportraw:
            appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
            is_path = os.path.isdir(appdata_path)
            if not is_path:
                os.makedirs(appdata_path)

            datepath = os.path.join(appdata_path, str(datetime.date.today()))
            datepathexists = os.path.isdir(datepath)
            if not datepathexists:
                os.makedirs(datepath)

            exportraw_path = os.path.join(
                datepath,
                str(datetime.datetime.now().replace(microsecond=0).time()).replace(
                    ":", ""
                ),
            )
            exportpath = exportraw_path
            log.debug(f"raw byte files exported to {exportraw_path}")
            if not os.path.isdir(exportraw_path):
                os.makedirs(exportraw_path)

        if args.export:
            if args.export_path:
                pcapng_path = args.export_path
                if not os.path.isabs(pcapng_path):
                    pcapng_path = os.path.abspath(pcapng_path)

                os.makedirs(os.path.dirname(pcapng_path), exist_ok=True)
                if os.path.isdir(pcapng_path):
                    pcapng_path = os.path.join(
                        pcapng_path,
                        f"lswifi_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng",
                    )
            else:
                appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
                is_path = os.path.isdir(appdata_path)
                if not is_path:
                    os.makedirs(appdata_path)

                pcapng_path = os.path.join(
                    appdata_path,
                    f"lswifi_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng",
                )
            # print(datetime.date.today())
            # print(str(datetime.datetime.now().replace(microsecond=0).time()).replace(":",""))
            # print(datetime.datetime.now().replace(microsecond=0).isoformat().replace(":",""))

        newapnames = {}

        bss_len = len(wireless_network_bss_list)

        if args.bytes:
            for index, bss in enumerate(wireless_network_bss_list):
                wlanapi_bss = str(bss.bssid).lower()
                if args.bytes:
                    user_bss = args.bytes.lower()
                if wlanapi_bss != user_bss:
                    # print("{} {}".format(wlanapi_bss, user_bss))
                    continue
                print(f"bss bytes:\n{bss.bssbytes.send()}\n\n)")
                print(f"bss octets:\n{format_bytes_as_hex(bss.bssbytes.send())}\n")
                print("bss base64:")
                bssb64 = str(
                    json.dumps(bss.bssbytes.send(), cls=Base64Encoder)
                ).replace('"', "")
                print(f"{bssb64}\n")
                print(f"ies bytes:\n{bytes(bss.iesbytes)}\n")
                print(f"ies octets:\n{format_bytes_as_hex(bss.iesbytes)}\n")
                # iesb64 = str(base64.b64encode(bss.iesbytes)).replace("'","").replace("b","")
                iesb64 = str(
                    json.dumps(bytes(bss.iesbytes), cls=Base64Encoder)
                ).replace('"', "")
                print(f"ies base64:\n{iesb64}\n")
        else:
            # WirelessNetworkBss object
            for index, bss in enumerate(wireless_network_bss_list):
                if args.ies or args.exportraw:
                    wlanapi_bss = str(bss.bssid).lower()
                    if args.ies:
                        user_bss = args.ies.lower().replace("-", ":").replace(".", ":")
                    if args.bytes:
                        user_bss = args.bytes.lower()
                    if args.exportraw:
                        if (
                            args.exportraw != "all"
                        ):  # if lswifi -export xx:xx:xx:nn:nn:nn
                            user_bss = args.exportraw
                            # print(f"{bss_len} {index}")
                            # print(f"{wlanapi_bss} {user_bss}")

                            if wlanapi_bss != user_bss:
                                # print("{} {}".format(wlanapi_bss, user_bss))
                                if bss_len == (index + 1):
                                    print(
                                        f"no match for {args.exportraw} found in scan results. please try again ..."
                                    )
                                continue

                        # if lswifi -export
                        export_bss = str(bss.bssid).lower().replace(":", "-")

                        bsspath = export_bss + ".bss"
                        # print(f"{os.path.join(exportpath, bss)}")
                        # print(f"{type(bss.bssbytes.send())}")
                        # print(f"{bss.bssbytes.send()}")
                        bssfile = open(os.path.join(exportraw_path, bsspath), "wb")
                        try:
                            bssfile.write(bss.bssbytes.send())
                        finally:
                            bssfile.close()

                        bsspath = export_bss + ".bss"
                        bssfile = open(os.path.join(exportraw_path, bsspath), "wb")
                        try:
                            bssfile.write(bss.bssbytes.send())
                        finally:
                            bssfile.close()

                            iespath = export_bss + ".ies"
                            # print(f"{os.path.join(exportpath, ies)}")
                            # print(f"{type(bss.iesbytes)}")
                            # print(f"{bss.iesbytes}")
                            iesfile = open(os.path.join(exportraw_path, iespath), "wb")
                            try:
                                iesfile.write(bss.iesbytes)
                            finally:
                                iesfile.close()

                            # print(f"{bsspath} {iespath}")
                            if args.export != "all":
                                log.info(
                                    f"found and exporting requested bssid from the scan results of {client.mac}."
                                )
                                print(
                                    f"raw byte files for {args.export} exported to {exportraw_path}"
                                )
                                break
                            elif (bss_len - 1) == index:
                                log.info(
                                    f"found and exporting {bss_len} bssids from the scan results of {client.mac}."
                                )
                                print(f"files exported to {exportraw_path}")

                            continue

                    # compare if bss from list is the same as the one the user wants details for
                    if wlanapi_bss != user_bss:
                        # print("{} {}".format(wlanapi_bss, user_bss))
                        continue
                    if args.ies:
                        log.info(
                            f"found requested bssid in the scan results from {client.mac}."
                        )
                        print(bss)
                    break

                # handle weakest rssi value we want to see displayed to the screen
                if args.all:
                    pass
                elif bss.rssi.value < args.sensitivity:
                    log.debug(
                        f"excluding {bss.bssid} ({bss.ssid}) because bss.rssi.value {bss.rssi.value} is < {args.sensitivity}"
                    )
                    continue

                # handle band filters
                if not args.a and not args.g and not args.six:
                    pass
                else:
                    # handle a band filter
                    if args.a and args.g and not args.six:
                        if is_two_four_band(bss.channel_frequency.value):
                            pass
                        if is_five_band(bss.channel_frequency.value):
                            pass
                        if is_six_band(bss.channel_frequency.value):
                            continue
                    if args.a and args.six and not args.g:
                        if is_two_four_band(bss.channel_frequency.value):
                            continue
                        if is_five_band(bss.channel_frequency.value):
                            pass
                        if is_six_band(bss.channel_frequency.value):
                            pass
                    if args.a and not args.six and not args.g:
                        if is_two_four_band(bss.channel_frequency.value):
                            continue
                        if is_five_band(bss.channel_frequency.value):
                            pass
                        if is_six_band(bss.channel_frequency.value):
                            continue
                    # handle g band filter
                    if args.g and args.six and not args.a:
                        if is_two_four_band(bss.channel_frequency.value):
                            pass
                        if is_five_band(bss.channel_frequency.value):
                            continue
                        if is_six_band(bss.channel_frequency.value):
                            pass
                    if args.g and not args.six and not args.a:
                        if is_two_four_band(bss.channel_frequency.value):
                            pass
                        if is_five_band(bss.channel_frequency.value):
                            continue
                        if is_six_band(bss.channel_frequency.value):
                            continue
                    # handle six band filter
                    if args.six and not args.a and not args.g:
                        if is_two_four_band(bss.channel_frequency.value):
                            continue
                        if is_five_band(bss.channel_frequency.value):
                            continue
                        if is_six_band(bss.channel_frequency.value):
                            pass

                # handle width filter
                if args.width is not None:
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

                if args.rnr:
                    for rnr in bss.rnrs:
                        rnr_out = []
                        for obj in rnr:
                            rnr_out.append(obj.out())
                        rnr_results.append(rnr_out)
                    continue

                # this is a list to check for dup bssids (may be expected for some APs which share same BSSID on 2.4 and 5 GHz radios - Cisco for example)
                bssid_list.append(str(bss.bssid))

                if args.ethers:
                    if bss.bssid.value in ethers:
                        bss.apname.value = ethers[bss.bssid.value]
                elif args.apnames:
                    if is_caching_acknowledged:
                        scan_bssid = bss.bssid.value
                        scan_apname = remove_control_chars(bss.apname.value)

                        if (
                            json_names.get(scan_bssid) is not None
                        ):  # if bssid is in json dict
                            cachedAP = json_names[scan_bssid]
                            bss.apname.value = cachedAP  # start with cached
                            if (
                                scan_apname != ""
                            ):  # if current AP name is not an empty string
                                if (
                                    scan_apname != cachedAP
                                ):  # if current AP doesn't match whats in the json
                                    newapnames[scan_bssid] = (
                                        scan_apname  # then 1) update new hash table with current AP name
                                    )
                                    bss.apname.value = scan_apname  # then 2) update the apname that will be displayed
                            log.debug(
                                f"BSSID from scan: {scan_bssid}, Name from cache: {cachedAP}, Name from scanned {scan_apname}"
                            )
                        elif scan_apname != "":  # working with new AP name
                            newapnames[scan_bssid] = (
                                scan_apname  # then 1) update new hash table with new AP name
                            )

                # bss.element.out() contains a tuple with the following values
                #   1. value, 2. header and alignment (left, center, right), 3. subheader

                if bss.bssid.connected:
                    if not args.json and not args.csv:
                        # if "(*)" not in bss.bssid.value:
                        bss.bssid.value += "(*)"

                if args.json:
                    json_out.append(
                        {
                            "timestamp": client.last_scan_time_iso,
                            "interface_mac": client.mac,
                            "amendments": sorted(bss.amendments.elements),
                            "apname": str(bss.apname).strip(),
                            "bssid": str(bss.bssid).strip(),
                            "bss_type": str(bss.bss_type).strip(),
                            "channel_frequency": str(bss.channel_frequency).strip(),
                            "channel_number": str(bss.channel_number).strip(),
                            "channel_width": str(bss.channel_width).strip(),
                            "connected": bss.bssid.connected,
                            "ies": sorted(bss.ie_numbers.elements),
                            "ies_extension": sorted(bss.exie_numbers.elements),
                            "modes": sorted(bss.modes.elements),
                            "pmf": str(bss.pmf).strip(),
                            "phy_type": str(bss.phy_type).strip(),
                            "rates_basic": [
                                x for x in bss.wlanrateset.basic.split(" ")
                            ],
                            "rates_data": [x for x in bss.wlanrateset.data.split(" ")],
                            "rssi": str(bss.rssi),
                            "security": str(bss.security).strip(),
                            "spatial_streams": str(bss.spatial_streams),
                            "ssid": str(bss.ssid),
                            "stations": str(bss.stations),
                            "uptime": str(bss.uptime).strip(),
                            "utilization": str(bss.utilization).strip(),
                        }
                    )
                if args.csv:
                    csv_out.append(
                        {
                            "timestamp": client.last_scan_time_iso,
                            "interface_mac": client.mac,
                            "amendments": "/".join(sorted(bss.amendments.elements)),
                            "apname": str(bss.apname).strip(),
                            "bssid": str(bss.bssid).strip(),
                            "bss_type": str(bss.bss_type).strip(),
                            "channel_frequency": str(bss.channel_frequency).strip(),
                            "channel_number": str(bss.channel_number).strip(),
                            "channel_width": str(bss.channel_width).strip(),
                            "connected": bss.bssid.connected,
                            "ies": "/".join(map(str, sorted(bss.ie_numbers.elements))),
                            "ies_extension": "/".join(
                                map(str, sorted(bss.exie_numbers.elements))
                            ),
                            "modes": "/".join(sorted(bss.modes.elements)),
                            "pmf": str(bss.pmf).strip(),
                            "phy_type": str(bss.phy_type).strip(),
                            "rates_basic": "/".join(
                                [x for x in bss.wlanrateset.basic.split(" ")]
                            ),
                            "rates_data": "/".join(
                                [x for x in bss.wlanrateset.data.split(" ")]
                            ),
                            "rssi": str(bss.rssi),
                            "security": str(bss.security).strip(),
                            "spatial_streams": str(bss.spatial_streams),
                            "ssid": bss.ssid,
                            "stations": str(bss.stations),
                            "utilization": str(bss.utilization).strip(),
                            "uptime": str(bss.uptime).strip(),
                        }
                    )
                out_results.append(
                    [
                        bss.ssid.out(),
                        bss.bssid.out(),
                        bss.rssi.out(),
                        bss.phy_type.out(),
                        bss.channel_number_marked.out(),
                        bss.channel_frequency.out(),
                        bss.spatial_streams.out(),
                        bss.amendments.out(),
                        # bss.security.out(),
                        bss.auth.out(),
                        bss.encryption.out(),
                        bss.pmf.out(),
                        bss.uptime.out(),
                    ]
                )

                if args.pmf:
                    out_results[-1].insert(len(out_results[-1]) - 1, bss.pmf.out())

                if args.period:
                    out_results[-1].append(bss.beacon_interval.out())

                if args.tpc:
                    out_results[-1].append(bss.transmit_power.out())

                if args.qbss:
                    out_results[-1].append(bss.stations.out())
                    out_results[-1].append(bss.utilization.out())

                if args.apnames or args.ethers:
                    if is_caching_acknowledged:
                        out_results[-1].append(bss.apname.out())

        rnr_results = sorted(
            rnr_results,
            key=lambda x: x[get_index("RSSI", rnr_results)].value,
            reverse=False,
        )

        if args.uptime:  # sort by uptime
            out_results = sorted(
                out_results,
                key=lambda x: int(
                    x[get_index("UPTIME", out_results)].value.split("d")[0]
                ),
                reverse=False,
            )
            csv_out = sorted(csv_out, key=itemgetter("uptime"), reverse=False)
            json_out = sorted(json_out, key=itemgetter("uptime"), reverse=False)
        else:  # sort by RSSI
            out_results = sorted(
                out_results,
                key=lambda x: x[get_index("RSSI", out_results)].value,
                reverse=False,
            )
            csv_out = sorted(csv_out, key=itemgetter("rssi"), reverse=False)
            json_out = sorted(json_out, key=itemgetter("rssi"), reverse=False)

        if args.json:
            json_file_exists = os.path.exists(json_file_name)
            if json_file_exists:
                mode = "r+"
            else:
                mode = "w"
            if not json_out:
                log.info(f"nothing found to export as JSON to {json_file_name}")
            else:
                log.info(f"exporting scans as JSON to {json_file_name}")
                with open(json_file_name, mode) as file:
                    if json_file_exists:
                        file_data = json.load(file)
                        file_data["scan_data"].append(json_out)
                        file.seek(0)
                        json.dump(file_data, file, indent=args.json_indent)
                    else:
                        file_data = json.dumps(
                            {
                                "lswifi": {"version": f"lswifi {__version__}"},
                                "scan_data": json_out,
                            },
                            indent=args.json_indent,
                        )
                        file.write(file_data)

        if args.csv:
            has_headings = False
            csv_file_exists = os.path.exists(csv_file_name)
            mode = "w"
            if csv_file_exists:
                mode = "a"
                with open(csv_file_name, "r") as f:
                    try:
                        has_headings = csv.Sniffer().has_header(f.read(4096))
                    except csv.Error:
                        # The file seems to be empty
                        has_headings = False

            if not csv_out:
                log.info(f"nothing found to export as CSV to {csv_file_name}")
            else:
                log.info(f"exporting scans as CSV to {csv_file_name}")
                with open(csv_file_name, mode, newline="") as csvfile:
                    fieldnames = csv_out[-1].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    # log.debug("does csv file likely already have headings written? %s" % ('Yes' if has_headings else 'No'))
                    if not has_headings:
                        writer.writeheader()
                        has_headings = True
                    for result in csv_out:
                        writer.writerow(result)

        if args.export and len(wireless_network_bss_list) > 0:
            pcap = PCAPNG(pcapng_path)
            networks_exported = 0

            try:
                with pcap:
                    interface_id = pcap.add_interface(
                        name=client.iface.description,
                        description=f"{client.mac}",
                    )

                    for bss in wireless_network_bss_list:
                        if args.export != "all":
                            if str(bss.bssid).lower() != args.export.lower():
                                continue

                        if not args.all and bss.rssi.value < args.sensitivity:
                            continue

                        if (
                            args.a or args.g or args.six
                        ) and not self._bss_matches_band_filter(bss, args):
                            continue

                        if args.width is not None and args.width not in str(
                            bss.channel_width
                        ):
                            continue

                        if args.include is not None and args.include not in str(
                            bss.ssid
                        ):
                            continue

                        if args.exclude and args.exclude in str(bss.ssid):
                            continue

                        if args.bssid is not None:
                            input_mac = strip_mac_address_format(args.bssid)
                            bss_mac = strip_mac_address_format(str(bss.bssid))
                            if input_mac not in bss_mac:
                                continue

                        frame_data = pcap.create_radiotap_frame(bss)
                        pcap.write_packet(
                            interface_id, client.last_scan_time_epoch, frame_data
                        )
                        networks_exported += 1

                if args.export != "all":
                    if networks_exported > 0:
                        log.info(f"Exported BSSID {args.export} to {pcapng_path}")
                        print(f"Exported BSSID {args.export} to {pcapng_path}")
                    else:
                        log.info(f"BSSID {args.export} not found or filtered out")
                else:
                    log.info(f"Exported {networks_exported} networks to {pcapng_path}")

            except Exception as e:
                log.error(f"Error exporting to pcapng: {str(e)}")
                print(f"Error exporting to pcapng: {str(e)}")

        if args.exportraw:
            for index, bss in enumerate(wireless_network_bss_list):
                wlanapi_bss = str(bss.bssid).lower()
                clean_wlanapi_bss = wlanapi_bss.replace("(*)", "")
                if args.exportraw != "all":
                    user_bss = args.exportraw
                    if clean_wlanapi_bss != user_bss:
                        if bss_len == (index + 1):
                            print(
                                f"No match for {args.exportraw} found in scan results. Please try again ..."
                            )
                        continue

                export_bss = clean_wlanapi_bss.replace(":", "-")

                bsspath = export_bss + ".bss"
                bssfile = open(os.path.join(exportpath, bsspath), "wb")
                try:
                    bssfile.write(bss.bssbytes.send())
                finally:
                    bssfile.close()

                iespath = export_bss + ".ies"
                iesfile = open(os.path.join(exportpath, iespath), "wb")
                try:
                    iesfile.write(bss.iesbytes)
                finally:
                    iesfile.close()

                if args.exportraw != "all":
                    log.info(
                        f"Found and exporting requested BSSID from the scan results of {client.mac}."
                    )
                    print(
                        f"Raw byte files for {args.exportraw} exported to {exportpath}"
                    )
                    break
                elif (bss_len - 1) == index:
                    log.info(
                        f"Found and exporting {bss_len} BSSIDs from the scan results of {client.mac}."
                    )
                    print(f"Files exported to {exportpath}")

        return (
            out_results,
            rnr_results,
            bss_len,
            bssid_list,
            json_names,
            json_out,
            newapnames,
        )

    def _bss_matches_band_filter(self, bss, args):
        """Check if a BSS matches the band filtering criteria"""
        if args.a and args.g and not args.six:
            if is_two_four_band(bss.channel_frequency.value):
                return True
            if is_five_band(bss.channel_frequency.value):
                return True
            if is_six_band(bss.channel_frequency.value):
                return False

        if args.a and args.six and not args.g:
            if is_two_four_band(bss.channel_frequency.value):
                return False
            if is_five_band(bss.channel_frequency.value):
                return True
            if is_six_band(bss.channel_frequency.value):
                return True

        if args.a and not args.six and not args.g:
            if is_two_four_band(bss.channel_frequency.value):
                return False
            if is_five_band(bss.channel_frequency.value):
                return True
            if is_six_band(bss.channel_frequency.value):
                return False

        if args.g and args.six and not args.a:
            if is_two_four_band(bss.channel_frequency.value):
                return True
            if is_five_band(bss.channel_frequency.value):
                return False
            if is_six_band(bss.channel_frequency.value):
                return True

        if args.g and not args.six and not args.a:
            if is_two_four_band(bss.channel_frequency.value):
                return True
            if is_five_band(bss.channel_frequency.value):
                return False
            if is_six_band(bss.channel_frequency.value):
                return False

        if args.six and not args.a and not args.g:
            if is_two_four_band(bss.channel_frequency.value):
                return False
            if is_five_band(bss.channel_frequency.value):
                return False
            if is_six_band(bss.channel_frequency.value):
                return True

        return True

    def decode_pcapng_file(self, args):
        """Parse scan results from a pcapng file"""
        log = logging.getLogger(__name__)

        if not os.path.isfile(args.decode):
            print(f"{args.decode} file does not exist on file system... exiting...")
            return

        try:

            class MockBssEntry:
                def __init__(self):
                    self.dot11Ssid = type("obj", (), {"SSID": b"", "SSIDLength": 0})()
                    self.PhyId = 0
                    self.dot11Bssid = None
                    self.dot11BssType = 1
                    self.dot11BssPhyType = 7
                    self.Rssi = -75
                    self.LinkQuality = 0
                    self.InRegDomain = True
                    self.BeaconPeriod = 100
                    self.Timestamp = 0
                    self.HostTimestamp = 0
                    self.CapabilityInformation = 0
                    self.ChCenterFrequency = 2412
                    self.WlanRateSet = type(
                        "obj", (), {"RateSetLength": 0, "RateSet": [0] * 126}
                    )()
                    self.IeOffset = 0
                    self.IeSize = 0
                    self.iesbytes = None

                def send(self):
                    return self.iesbytes

            pcap = PCAPNG(args.decode, mode="r")
            networks = []

            with pcap:
                for (
                    interface_id,
                    interface_name,
                    timestamp,
                    packet_data,
                ) in pcap.get_packets():
                    # log.debug("\\\\\\")
                    try:
                        if len(packet_data) < 36:
                            continue

                        header_len = struct.unpack_from("<BBH", packet_data, 0)[2]

                        if header_len < 8 or header_len > len(packet_data):
                            continue

                        frame_data = packet_data[header_len:]

                        if len(frame_data) < 2:
                            continue

                        frame_control = struct.unpack("<H", frame_data[:2])[0]
                        frame_type = (frame_control & 0x000C) >> 2
                        frame_subtype = (frame_control & 0x00F0) >> 4

                        if frame_type != 0 or frame_subtype != 8:
                            continue

                        if len(frame_data) < 22:
                            continue

                        bssid = frame_data[16:22]

                        rssi = -99
                        present = struct.unpack_from("<I", packet_data, 4)[0]
                        if present & 0x00000020:
                            offset = 8
                            if present & 0x00000001:
                                offset += 8
                            if present & 0x00000002:
                                offset += 1
                            if present & 0x00000004:
                                offset += 1
                            if present & 0x00000008:
                                offset += 4
                            if present & 0x00000010:
                                offset += 2

                            if offset < header_len:
                                rssi = struct.unpack(
                                    "b", packet_data[offset : offset + 1]
                                )[0]

                        freq = 0
                        if present & 0x00000008:
                            freq_offset = 8
                            if present & 0x00000001:
                                freq_offset += 8
                            if present & 0x00000002:
                                freq_offset += 1
                            if present & 0x00000004:
                                freq_offset += 1

                            if freq_offset + 2 <= header_len:
                                freq = struct.unpack(
                                    "<H", packet_data[freq_offset : freq_offset + 2]
                                )[0]

                        ssid = b""
                        if len(frame_data) >= 38:
                            ie_offset = 36
                            if frame_data[ie_offset] == 0:
                                ie_len = frame_data[ie_offset + 1]
                                if ie_len <= 32 and ie_offset + 2 + ie_len <= len(
                                    frame_data
                                ):
                                    ssid = frame_data[
                                        ie_offset + 2 : ie_offset + 2 + ie_len
                                    ]

                        capabilities = 0
                        if len(frame_data) >= 36:
                            capabilities = struct.unpack("<H", frame_data[34:36])[0]

                        beacon_period = 100
                        if len(frame_data) >= 34:
                            beacon_period = struct.unpack("<H", frame_data[32:34])[0]

                        ies_data = frame_data[36:] if len(frame_data) > 36 else b""
                        buffer = create_string_buffer(ies_data)
                        buffer_type = POINTER(type(buffer))
                        ies_data = cast(buffer, buffer_type).contents

                        mock_bss = MockBssEntry()
                        mock_bss.dot11Bssid = bssid
                        mock_bss.dot11Ssid.SSID = ssid
                        mock_bss.dot11Ssid.SSIDLength = len(ssid)
                        mock_bss.Rssi = rssi
                        mock_bss.ChCenterFrequency = freq * 1000
                        mock_bss.BeaconPeriod = beacon_period
                        mock_bss.CapabilityInformation = capabilities
                        mock_bss.Timestamp = timestamp
                        mock_bss.iesbytes = ies_data

                        bss = WirelessNetworkBss(
                            mock_bss, is_pcapng=True, pcapng_ies=ies_data
                        )
                        bssid_str = ":".join(f"{b:02x}" for b in bssid)

                        bss.ssid.value = ssid.decode("utf-8", errors="replace")
                        bss.bssid.value = bssid_str
                        bss.rssi.value = rssi

                        # convert channel frequency unit from MHz to GHz
                        # 2412 to 2.412, 5825 to 5.825, 6855 to 6.855
                        bss.channel_frequency.value = f"{freq}"
                        bss.channel_frequency.value = "{0:.3f}".format(
                            int(bss.channel_frequency.value) / 1000
                        )

                        bss.ie_rates.value = bss.parse_rates(bss.ie_rates)

                        if len(bss.channel_number_marked) == 1:
                            bss.channel_number_marked.value = (
                                f"  {bss.channel_number_marked}"
                            )
                        if len(bss.channel_number_marked) == 2:
                            bss.channel_number_marked.value = (
                                f" {bss.channel_number_marked}"
                            )

                        bss.channel_number_marked.value = f"{bss.channel_number}@{bss.channel_width}{bss.channel_marking}"

                        networks.append(bss)
                        # log.debug("///")
                    except Exception as e:
                        trace = traceback.format_exc()
                        line_number = traceback.extract_tb(sys.exc_info()[2])[-1][1]
                        error_msg = (
                            f"Error processing packet: {line_number}: {str(e)}\n{trace}"
                        )
                        log.error(error_msg)
                        # log.debug("///")
                        continue

            if networks:

                class TempClient:
                    def __init__(self, networks):
                        self.data = networks
                        self.mac = "pcapng file"
                        self.iface = type(
                            "obj",
                            (object,),
                            {
                                "connection_name": "pcapng file",
                                "description": "pcapng file",
                                "guid_string": "pcapng file",
                            },
                        )
                        self.last_scan_time_iso = datetime.datetime.now().isoformat()
                        self.last_scan_time_epoch = time.time()

                client = TempClient(networks)
                (
                    out_results,
                    rnr_results,
                    bss_len,
                    bssid_list,
                    json_names,
                    json_out,
                    newapnames,
                ) = self.parse_bss_list(
                    client,
                    False,
                    args.csv if hasattr(args, "csv") else "",
                    args.json if hasattr(args, "json") else "",
                    args,
                )

                if args.rnr:
                    self.print_rnr_list(rnr_results, client.mac, args)
                else:
                    if not args.ies:
                        self.print_bss_list(
                            out_results,
                            bss_len,
                            client.mac,
                            bssid_list,
                            False,
                            json_names,
                            json_out,
                            newapnames,
                            args,
                        )
            else:
                log.info(f"No networks found in {args.decode}")

        except Exception as e:
            trace = traceback.format_exc()
            line_number = traceback.extract_tb(sys.exc_info()[2])[-1][1]
            error_msg = (
                f"Error parsing pcapng file at line {line_number}: {str(e)}\n{trace}"
            )
            log.error(error_msg)

    def print_rnr_list(self, rnr_results: list, client_mac, args):
        log = logging.getLogger(__name__)
        if args.all:
            log.info(
                f"Reduced Neighbor Reports found in {len(rnr_results)} BSSIDs from scan results for {client_mac}."
            )
        else:
            log.info(
                f"display filter sensitivity {args.sensitivity}; "
                f"Reduced Neighbor Reports found in {len(rnr_results)} BSSIDs from scan results for {client_mac}."
            )

        if len(rnr_results) > 0:
            headers = []
            subheaders = []

            for tup in rnr_results[0]:
                headers.append(tup.header)
                subheaders.append(tup.subheader)

            result = ""

            rnr_results.insert(0, headers)
            rnr_results.insert(1, subheaders)

            border = ()
            rnr_results_len = len(rnr_results[0]) - 1
            for index, _item in enumerate(rnr_results[0]):
                if index == rnr_results_len:
                    max_len = len(_item)
                max_len = max(len(x) for x in [y[index] for y in rnr_results])
                border = border + (
                    generate_pretty_separator(
                        max_len, DECORS, DECORS_START, DECORS_END
                    ),
                )

                align = [y[index] for y in rnr_results][0].alignment.value

                if index == rnr_results_len:
                    result += f"{{{index}}}"
                else:
                    result += f"{{{index}:{align}{max_len}}}  "

            rnr_results.insert(0, border)
            rnr_results.insert(3, border)

            for row in rnr_results:
                rnr_results = []
                for data in row:
                    if isinstance(data, OUT_TUPLE):
                        rnr_results.append(f"{data.value}")
                    else:
                        rnr_results.append(f"{data}")
                print(result.format(*tuple(rnr_results)))

    def print_bss_list(
        self,
        scan_results,
        bss_len,
        client_mac,
        bssid_list,
        is_caching_acknowledged,
        json_names,
        json_out,
        newapnames,
        args,
    ):
        log = logging.getLogger(__name__)
        if args.all:
            log.info(
                f"output includes {len(scan_results)} of {bss_len} BSSIDs detected in scan results for {client_mac}."
            )
        else:
            log.info(
                f"display filter sensitivity {args.sensitivity}; "
                f"output includes {len(scan_results)} of {bss_len} BSSIDs detected in scan results for {client_mac}."
            )

        if len(scan_results) > 0:
            connected = False
            headers = []
            subheaders = []

            # check for substring that indicates the scanning interface is also connected to a BSSID found in results
            for result in scan_results:
                for data in result:
                    if "(*)" in str(data):
                        connected = True

            for tup in scan_results[0]:
                headers.append(tup.header)

            for tup in scan_results[0]:
                if "BSSID" in tup.header.value:
                    if connected:
                        tup.subheader = SubHeader("(*): connected")
                subheaders.append(tup.subheader)

            result_indexes_string = ""

            # add column header and subheader
            scan_results.insert(0, headers)
            scan_results.insert(1, subheaders)

            scan_results_len = len(scan_results[0]) - 1
            border = ()
            for index, _item in enumerate(scan_results[0]):
                # print(index, item)
                if index == scan_results_len:
                    max_len = len(_item)
                else:
                    max_len = max(len(x) for x in [y[index] for y in scan_results])
                border = border + (
                    generate_pretty_separator(
                        max_len, DECORS, DECORS_START, DECORS_END
                    ),
                )

                if index == scan_results_len:
                    result_indexes_string += f"{{{index}}}"
                else:
                    try:
                        first_item = [y[index] for y in scan_results][0]
                        if hasattr(first_item, "alignment") and hasattr(
                            first_item.alignment, "value"
                        ):
                            align = first_item.alignment.value
                        else:
                            align = "<"
                    except (AttributeError, IndexError):
                        align = "<"

                    result_indexes_string += f"{{{index}:{align}{max_len}}}  "

            scan_results.insert(0, border)
            scan_results.insert(3, border)

            # print results
            if not args.json:
                for result in scan_results:
                    scan_results = []
                    for data in result:
                        if isinstance(data, OUT_TUPLE):
                            scan_results.append(f"{data.value}")
                        else:
                            scan_results.append(f"{data}")

                    # print(type(result_indexes_string))
                    # print(result_indexes_string)
                    # print(scan_results)
                    print(result_indexes_string.format(*tuple(scan_results)))
            else:
                print(json.dumps(json_out))

        duplicates = set([x for x in bssid_list if bssid_list.count(x) > 1])
        if duplicates:
            log.warning("***BSSIDS WITH DUPLICATE MACs***")
            log.warning(duplicates)
            log.warning("***BSSIDS WITH DUPLICATE MACs***")

        if args.apnames:
            if is_caching_acknowledged:
                self.updateAPNames(json_names, newapnames)

    def decode_bytefile(self, args):
        if os.path.isfile(args.decoderaw):
            if args.decoderaw.lower().rsplit(".", 1)[1] == "ies":
                fh = open(args.decoderaw, "rb")
                ies = ""
                try:
                    _bytearray = bytearray(fh.read())
                    print(
                        f"Raw Information Elements ({len(_bytearray)} "
                        f"bytes):\n{format_bytes_as_hex(_bytearray)}"
                    )

                    print()
                    ies = WirelessNetworkBss.decode_bytefile_ies(_bytearray)
                finally:
                    fh.close()

                out = "Decoded Information Elements:\n"

                length_len = get_attr_max_len(ies, "length")
                id_len = get_attr_max_len(ies, "eid")
                names_len = get_attr_max_len(ies, "name")
                data_len = get_attr_max_len(ies, "pbody")
                get_attr_max_len(ies, "decoded")

                out += "{0:<{length_len}}  {1:<{id_len}}  {2:<{names_len}}  {3:<{data_len}}  {4}\n".format(
                    "Length",
                    "ID",
                    "Information Element",
                    "Raw Data",
                    "Decoded",
                    length_len=length_len,
                    data_len=data_len,
                    id_len=id_len,
                    names_len=names_len,
                )

                for ie in ies:
                    # if ie.element_id != 11:
                    #    continue
                    # Length, ID, Information Elements, Parsed, Details

                    # _hex = ""
                    # for _decimal in ie.body:
                    #    _hex = _hex + "{:02x} ".format(_decimal)
                    # _hex = _hex + "{}".format(hex(_decimal)[2:])
                    out += "{0:<{length_len}}  {1:<{id_len}}  {2:<{names_len}}  {3:<{data_len}}  {4}\n".format(
                        ie.length,
                        ie.eid,
                        ie.name,
                        ie.pbody,
                        ie.decoded,
                        length_len=length_len,
                        data_len=data_len,
                        id_len=id_len,
                        names_len=names_len,
                    )
                print(out)
                return

            if args.decoderaw.lower().rsplit(".", 1)[1] == "bss":
                fh = open(args.decoderaw, "rb")
                ies = ""
                try:
                    _bytearray = bytearray(fh.read())
                    print(
                        f"Raw BSS ({len(_bytearray)} bytes):\n{format_bytes_as_hex(_bytearray)}"
                    )
                    print()
                    print(
                        "Decoded BSS Information (NOTE: this is missing information found in .ies file):"
                    )
                    bss_entry = WLAN_API.WLANBSSEntry.from_buffer(_bytearray)
                    data = WirelessNetworkBss(bss_entry, is_byte_input_file=True)
                    print(data)
                finally:
                    fh.close()
        else:
            print(f"{args.decoderaw} file does not exist on file system... exiting...")


def run(args, **kwargs) -> None:
    """Run the application."""
    lswifi().run(args, **kwargs)
