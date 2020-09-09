# -*- coding: utf-8 -*-

"""
lswifi.appsetup
~~~~~~~~~~~~~~

Provides init functions that are used to help set up the app.
"""

from .__version__ import __version__

import argparse
import textwrap
import logging
import logging.config


class ExportAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not values:
            values = 4
        setattr(namespace, self.dest, values)


def setup_logger(args) -> logging.Logger:
    default_logging = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"}
        },
        "handlers": {
            "default": {
                "level": args.debug,
                "formatter": "standard",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": args.debug}},
    }
    logging.config.dictConfig(default_logging)
    return logging.getLogger(__name__)


def setup_parser() -> argparse:
    """Setup the parser for arguments passed into the module from the CLI.

    Returns:
        argparse object.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """            
            basic usage examples:
            ---------------------

            Print detected nearby Wi-Fi networks:
              >lswifi

            Print nearby Wi-Fi networks with a perceived signal strength of -60 dBm or greater:
              >lswifi -t -60

            Print Wi-Fi networks based on SSID filter (supports partial match):
              >lswifi -include my_ssid

            Print only 2.4 GHz or 5.0 GHz Wi-Fi Networks:
              >lswifi -g
              >lswifi -a

            Print the BSSID of the connected AP:
              >lswifi -ap

            Print the channel of the connected AP:
              >lswifi -channel

            Print only networks with BSSIDs that contain <mac> (supports partial match):
              >lswifi -bssid 06:6D:15:88:81:59

            Print additional details (inc. information elements) for a particular BSSID <mac>:
              >lswifi 06:6D:15:88:81:59
             """
        ),
        epilog=f"Made with Python by Josh Schmelzle",
        fromfile_prefix_chars="@",
    )
    parser.add_argument(
        "-version", "-V", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-iface", dest="iface", metavar="INTERFACE", help="what iface to use"
    )
    parser.add_argument(
        "-ies",
        type=str,
        metavar="BSSID",
        nargs="?",
        help="print information elements for given BSSID(s)",
    )
    parser.add_argument(
        "-a", action="store_true", help="filter results by the 5 GHz band only"
    )
    parser.add_argument(
        "-g", action="store_true", help="filter results by the 2.4 GHz band only"
    )
    parser.add_argument(
        "-threshold",
        "-t",
        metavar="dBm",
        dest="sensitivity",
        help="threshold used to filter out weak Wi-Fi signals",
    )
    parser.add_argument(
        "-include",
        dest="include",
        metavar="SSID",
        help="print results from a directed scan for a specific SSID",
    )
    parser.add_argument(
        "-exclude", dest="exclude", metavar="SSID", help="SSID exclude filter"
    )
    parser.add_argument(
        "-b",
        "-bssid",
        dest="bssid",
        metavar="BSSID",
        help="Set a 802.11 access point to filter for.",
    )
    parser.add_argument(
        "--ap-names",
        dest="apnames",
        action="store_true",
        help="use locally cached apnames files for the AP names",
    )
    parser.add_argument(
        "-uptime",
        dest="uptime",
        action="store_true",
        help="sort by access point uptime based on beacon timestamp.",
    )
    parser.add_argument(
        "--channel-width",
        dest="width",
        metavar="20|40|80|160",
        help="performs a directed scan for BSSIDs that have a specific channel width",
    )
    # parser.add_argument(
    #    "-acm", dest="acm", action="store_true", help="print WMM AC ACM values"
    # )
    parser.add_argument(
        "-ethers",
        dest="ethers",
        action="store_true",
        help="use ethers files for the AP names",
    )
    parser.add_argument(
        "--append-ethers",
        metavar="BSSID,APNAME",
        dest="append",
        help="append BSSID and AP name to ethers file for AP names",
    )
    parser.add_argument(
        "--data-location",
        dest="data_location",
        action="store_true",
        help="displays where config items are stored on the local machine",
    )
    parser.add_argument(
        "-ap",
        dest="get_current_ap",
        action="store_true",
        help="print the BSSID of the connected AP",
    )
    parser.add_argument(
        "-channel",
        "-c",
        dest="get_current_channel",
        action="store_true",
        help="print the channel of the connected AP",
    )
    parser.add_argument(
        "-raw",
        dest="raw",
        action="store_true",
        help="format output as the raw value for other scripts",
    )
    parser.add_argument(
        "--get-interfaces",
        dest="get_interface_info",
        action="store_true",
        help="print current Wi-Fi status and information",
    )
    parser.add_argument(
        "--list-interfaces",
        dest="list_interfaces",
        action="store_true",
        help="print a list of available WLAN interfaces",
    )
    parser.add_argument("--supported", dest="supported", action="store_true")
    # parser.add_argument(
    #    "--json",
    #    "-j",
    #    dest="json",
    #    action="store_true",
    #    help="output will be formatted as json",
    # )
    # parser.add_argument(
    #    "--keepalive",
    #    "-k",
    #    action="store_true",
    #    help="a keepalive to monitor and display scan results on scan complete events",
    # )
    parser.add_argument(
        "-export",
        nargs="?",
        type=str,
        metavar="BSSID",
        dest="export",
        action=ExportAction,
        help="export bss and ies bytefiles. by default exports all from scan. provide mac to export specific",
    )
    parser.add_argument(
        "-decode",
        dest="bytefile",
        metavar="BYTEFILE",
        help="decode raw .BSS or .IES file",
    )
    parser.add_argument(
        "--bytes",
        metavar="BSSID",
        dest="bytes",
        help="lists the scan results in raw byte form for remote troubleshooting.",
    )
    parser.add_argument(
        "--watchevents", dest="event_watcher", action="store_true", help="watch events"
    )
    parser.add_argument(
        "--debug",
        action="store_const",
        help="increase output for debugging",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    return parser
