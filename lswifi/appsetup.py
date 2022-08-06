# -*- coding: utf-8 -*-

"""
lswifi.appsetup
~~~~~~~~~~~~~~~

Provides init functions that are used to help set up the app.
"""

import argparse
import logging
import logging.config
import textwrap

from .__version__ import __version__


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
                "stream": "ext://sys.stderr",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": args.debug}},
    }
    logging.config.dictConfig(default_logging)
    return logging.getLogger(__name__)


def setup_parser() -> argparse.ArgumentParser:
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

            Print only 2.4 GHz, 5 GHz, or 6 GHz Wi-Fi Networks:
              >lswifi -g
              >lswifi -a
              >lswifi -six

            Print the BSSID of the connected AP:
              >lswifi -ap

            Print the channel of the connected AP:
              >lswifi -channel

            Print only networks with BSSIDs that contain <mac>:
              >lswifi -bssid 06:6D:15:88:81:59

            Print additional details (inc. information elements) for a particular BSSID <mac>:
              >lswifi -ies 06:6D:15:88:81:59
              
            Print and add detected AP names column in output:
              >lswifi --ap-names
              
            Print and add QBSS stations and utilization columns in output:
              >lswifi --qbss

            Watch event notifications (inc. roaming, connection, scanning, etc.):
              >lswifi --watchevents
             """
        ),
        epilog=f"Made with Python by Josh Schmelzle",
        fromfile_prefix_chars="@",
    )
    parser.add_argument("-version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-iface", dest="iface", metavar="INTERFACE", help="set which interface to use"
    )
    parser.add_argument(
        "-ies",
        type=str,
        metavar="BSSID",
        nargs="?",
        help="print extra information about information elements for a specified BSSID",
    )
    parser.add_argument(
        "-threshold",
        "-t",
        metavar="dBm",
        dest="sensitivity",
        help="threshold which excludes networks with weak signal strength (-82 is default)",
    )
    parser.add_argument(
        "-g",
        action="store_true",
        help="display filter to limit output by 2.4 GHz band",
    )
    parser.add_argument(
        "-a",
        action="store_true",
        help="display filter to limit output by 5 GHz band",
    )
    parser.add_argument(
        "-six",
        action="store_true",
        help="display filter to limit output by 6 GHz band",
    )
    parser.add_argument(
        "-include",
        dest="include",
        metavar="SSID",
        help="display filter to limit results by specified SSIDs (partial matching supported)",
    )
    parser.add_argument(
        "-exclude",
        dest="exclude",
        metavar="SSID",
        help="display filter to exclude results by specified SSIDs (partial matching supported)",
    )
    parser.add_argument(
        "-bssid",
        dest="bssid",
        metavar="BSSID",
        help="display filter to limit results by specified BSSIDs (partial matching supported)",
    )
    parser.add_argument(
        "--ap-names",
        dest="apnames",
        action="store_true",
        help="adds an ap name column to output and will cache ap names locally to help provide consistent results",
    )
    parser.add_argument(
        "--qbss",
        dest="qbss",
        action="store_true",
        help="adds station and utilization columns to output using information from AP beacon QBSS IE",
    )
    parser.add_argument(
        "--tpc",
        dest="tpc",
        action="store_true",
        help="adds TPC column to output using information from AP beacon 802.11h",
    )
    parser.add_argument(
        "--mfp",
        "--pmf",
        dest="pmf",
        action="store_true",
        help="adds Protected Management Frame column to output using information from AP beacon RSNE",
    )
    parser.add_argument(
        "--interval",
        dest="interval",
        action="store_true",
        help="adds beacon period column to output using information from AP beacon",
    )
    parser.add_argument(
        "-uptime",
        "--uptime",
        dest="uptime",
        action="store_true",
        help="sort output by access point uptime based on beacon timestamp",
    )
    parser.add_argument(
        "--channel-width",
        dest="width",
        metavar="20|40|80|160",
        help="display filter to limit output by a specified channel width",
    )
    parser.add_argument(
        "-ethers",
        dest="ethers",
        action="store_true",
        help="display ap name column and use ethers files for the names",
    )
    parser.add_argument(
        "--append-ethers",
        metavar="BSSID,APNAME",
        dest="append",
        help="append BSSID and AP name to ethers file for AP names",
    )
    parser.add_argument(
        "--display-ethers",
        dest="display_ethers",
        action="store_true",
        help="display the list of saved ethers; (BSSID,APNAME) mapping",
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
        dest="get_current_channel",
        action="store_true",
        help="print the channel of the connected AP",
    )
    parser.add_argument(
        "-raw",
        dest="raw",
        action="store_true",
        help="format output as the raw value for other scripts (for -ap and -channel only)",
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
    parser.add_argument(
        "--supported", dest="supported", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--json",
        dest="json",
        action="store_true",
        help="output will be formatted as json",
    )
    parser.add_argument(
        "-export",
        nargs="?",
        type=str,
        metavar="BSSID",
        dest="export",
        action=ExportAction,
        help="export bss and ies bytefiles. default behavior will export all scan. to export one, specify mac address as argument.",
    )
    parser.add_argument(
        "-decode",
        dest="bytefile",
        metavar="BYTEFILE",
        help="decode a raw .BSS or .IES file",
    )
    parser.add_argument(
        "--bytes",
        metavar="BSSID",
        dest="bytes",
        help="output debugging bytes for a specified BSSID.",
    )
    parser.add_argument(
        "--watchevents",
        dest="event_watcher",
        action="store_true",
        help="a special mode which watches for notification on a wireless interface such as connection and roaming events",
    )
    parser.add_argument(
        "--debug",
        action="store_const",
        help="increase verbosity in output for debugging",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    return parser
