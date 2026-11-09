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
lswifi.lswifi
~~~~~~~~~~~~~

a CLI Wi-Fi scanning utility for Windows that leverages Microsofts Native Wifi wlanapi.h
"""

import argparse
import logging
import os
import platform
import sys

# hard set no support for Python versions < 3.11
if sys.version_info < (3, 11):  # noqa: UP036
    print(
        f"lswifi requires Python 3.11+. \nyour active Python version is {platform.python_version()}.\nexiting..."
    )
    sys.exit(-1)

# app imports
from lswifi import app, appsetup, rssistats, updatecheck
from lswifi.backends.base import BackendError
from lswifi.backends.factory import get_backend, needs_backend
from lswifi.constants import APNAMEACKFILE, APNAMEJSONFILE
from lswifi.helpers import app_data_dir


def app_path():
    appdata_path = app_data_dir()
    path_exists = os.path.isdir(appdata_path)
    if not path_exists:
        os.makedirs(appdata_path)
    print(f"{appdata_path}")


def main():
    is_apname_ack_stored = False
    parser = appsetup.setup_parser()

    completion_result = appsetup.parse_completion_args(sys.argv[1:])
    if completion_result is not None:
        args_str, current_word = completion_result
        appsetup.handle_completion(args_str, current_word)
        return

    args = parser.parse_args()
    if args.rssi_stats:
        probe = parser.parse_args(namespace=argparse.Namespace(sensitivity=None))
        if probe.sensitivity is not None:
            parser.error(
                "-threshold (-t) is incompatible with --rssi-stats: this mode never filters readings, so the spread is not skewed"
            )
        filters = [
            flag
            for flag, given in (
                ("-a", args.a),
                ("-g", args.g),
                ("-six", args.six),
                ("--channel-width", args.width is not None),
            )
            if given
        ]
        if filters:
            parser.error(
                f"{', '.join(filters)} {'is' if len(filters) == 1 else 'are'} incompatible with --rssi-stats: this mode measures every band and channel width, and each band gets its own summary"
            )
        outputs = [
            flag
            for flag, given in (
                ("-ies", args.ies is not None),
                ("--bytes", args.bytes is not None),
                ("-export", args.export is not None),
                ("-exportraw", args.exportraw is not None),
            )
            if given
        ]
        if outputs:
            parser.error(
                f"{', '.join(outputs)} {'is' if len(outputs) == 1 else 'are'} incompatible with --rssi-stats: run them without --rssi-stats"
            )
        if args.bssid is not None and not rssistats.is_bssid_prefix(args.bssid):
            parser.error(
                f"--rssi-stats needs a BSSID or a prefix of 1 to 6 octets for -bssid, such as 00:00:5e:00:53:01 or 00:00:5e, not {args.bssid}"
            )
        if not args.scans and not args.time:
            args.scans = "10"
        if not args.interval:
            args.interval = "2"
        args.all = True
    if args.exportraw and args.export_path:
        target = app.exportraw_dir(args.export_path)
        if os.path.isfile(target):
            parser.error(
                f"-path {args.export_path} is a file; -exportraw needs a directory"
            )
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as error:
            parser.error(f"-path {args.export_path}: {error.strerror or error}")
    appsetup.setup_logger(args)
    log = logging.getLogger(__name__)
    log.debug(f"args {args}")
    log.debug(f"{sys.version}")

    if hasattr(args, "command") and args.command == "completion":
        script = appsetup.get_completion_script(args.shell)
        if script:
            print(script)
        else:
            print(f"Unknown shell: {args.shell}", file=sys.stderr)
            sys.exit(1)
        return

    if args.data_location:
        app_path()
        sys.exit()

    updatecheck.notify(args)

    # parse args first; only commands that scan or query an adapter need a
    # backend. -decode and -decoderaw work on any OS.
    backend = None
    if needs_backend(args):
        try:
            backend = get_backend()
        except BackendError as error:
            print(f"lswifi: {error}", file=sys.stderr)
            sys.exit(-1)

    if args.apnames:
        is_apname_ack_stored = user_ack_apnames_disclaimer()
        log.debug(
            "is there a stored acknowledgement for caching apnames on local machine? %s",
            "Yes" if is_apname_ack_stored else "No",
        )

    app.run(args, storedack=is_apname_ack_stored, backend=backend)


def user_ack_apnames_disclaimer():
    """retrieve ack from user that BSSIDs and discovered apnames will be cached in appdata"""
    logger = logging.getLogger(__name__)
    appdata_folder = app_data_dir()
    is_path = os.path.isdir(appdata_folder)
    if not is_path:
        os.makedirs(appdata_folder)
        logger.debug("%s created? %s", appdata_folder, os.path.isdir(appdata_folder))
    ack = os.path.join(appdata_folder, APNAMEACKFILE)
    apnames = os.path.join(appdata_folder, APNAMEJSONFILE)
    if os.path.isfile(ack):
        return True
    else:
        print(
            "Running lswifi with --ap-names will cache detected AP names.\n\n"
            "Why?\n"
            "  - AP names are typically identified in beacon frames.\n"
            "  - The frame types in the scan results vary.\n"
            "  - Given data for a BSSID can be from a beacon or probe response.\n"
            "  - This is because a scan might not dwell on a channel long enough to hear a beacon.\n"
            "  - Dwell time varies per channel and can be shorter than the standard beacon interval.\n\n"
            "Where?\n"
            "  - Cached data is stored and read from a JSON file on your device here:\n\n"
        )
        print(f"{apnames}")
        try:
            text = input(
                "Please acknowledge storage and caching of AP names to enable feature (yes/no): "
            )
        except KeyboardInterrupt:
            print("\n\nDetected KeyboardInterrupt... Exiting...")
            sys.exit(-1)
        except EOFError:
            print()
            logger.warning(
                "no answer to the AP name caching prompt (input is not interactive); AP name caching stays off. run lswifi --ap-names once in a terminal to enable it"
            )
            return False
        if "y" in text.lower()[:1]:
            with open(ack, "w"):
                pass  # we only need a placeholder file
            print(
                "\nAP name caching is now enabled and we've recorded your response here: \n\n"
            )
            print(f"{ack}\n\n")
            print("If you'd like to disable this feature delete the file.\n")
            return True
        else:
            return False


def init():
    """Handle main init."""
    if __name__ == "__main__":
        main()
        sys.exit(0)


init()
