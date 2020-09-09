# -*- coding: utf-8 -*-

"""
lswifi.lswifi
~~~~~~~~~

a CLI Wi-Fi scanning utility for Windows that leverages Microsofts Native Wifi wlanapi.h
"""

import sys
import platform
import os
import logging
import asyncio
from signal import SIGINT, SIGTERM

# hard set no support for non win32 platforms
if sys.platform == "win32":
    pass
else:
    print(f"{os.path.basename(__file__)} only works on win32... exiting...")
    sys.exit(-1)

# hard set no support for Python versions < 3.7
if sys.version_info < (3, 7):
    print(
        f"{os.path.basename(__file__)} requires Python 3.7+. "
        f"your active Python version is {platform.python_version()}. "
        f"exiting..."
    )
    sys.exit(-1)

# app imports
from . import appsetup
from . import core
from .constants import APNAMEACKFILE, APNAMEJSONFILE


def app_path() -> None:
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), "lswifi")
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        os.makedirs(parentexportpath)
    print(f"{parentexportpath}")


def main():
    is_apname_ack_stored = False
    parser = appsetup.setup_parser()
    args = parser.parse_args()
    log = appsetup.setup_logger(args)
    log.debug(f"args {args}")
    log.debug(f"{sys.version}")
    if args.data_location:
        app_path()
        sys.exit(0)
    if args.apnames:
        is_apname_ack_stored = user_ack_apnames_disclaimer()
        log.debug(
            f"is there a stored ack for caching apnames on local machine? ({is_apname_ack_stored})"
        )

    loop = asyncio.get_event_loop()
    # pass in args and kwargs?
    main_task = asyncio.ensure_future(core.scan(args, storedack=is_apname_ack_stored))
    # loop.add_signal_handler(SIGINT, main_task.cancel)
    # loop.add_signal_handler(SIGTERM, main_task.cancel)
    try:
        # asyncio.run(core.scan(args, storedack=is_apname_ack_stored))
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        log.warning("caught KeyboardInterrupt... stopping...")
    except SystemExit:
        pass
    finally:
        loop.close()


def user_ack_apnames_disclaimer() -> bool:
    """ tell user that BSSIDs and apnames will be cached in appdata """
    parentexportpath = os.path.join(os.getenv("LOCALAPPDATA"), "lswifi")
    parentexportpathexists = os.path.isdir(parentexportpath)
    if not parentexportpathexists:
        log.debug(os.makedirs(parentexportpath))
    ackfilefp = os.path.join(parentexportpath, APNAMEACKFILE)
    apnamesfilename = os.path.join(parentexportpath, APNAMEJSONFILE)
    if os.path.isfile(ackfilefp):
        return True
    else:
        print(
            "--\n"
            "Access Point (AP) names are not in every scan result.\n\n"
            "Why?\n"
            "  - AP names are inside beacons.\n"
            "  - Retrieved scan results are based on beacons, probe responses, or sometimes both.\n"
            "What?\n"
            "  - This feature locally caches BSSIDs and their detected corresponding AP names.\n"
            "  - Doing this helps more consistently provide AP names in output.\n"
            "Where?\n"
            "  - They are stored and read from a JSON file on your device here:\n\n"
            f"{apnamesfilename}\n"
            "--\n"
        )
        text = input("Do you want to enable this feature? yes/no: ")
        if "y" in text.lower()[:1]:
            with open(ackfilefp, "w") as file:
                pass
            print(
                "--\n"
                "This feature has been enabled and your response stored here: \n\n"
                f"{ackfilefp}\n\n"
                "Want to disable this feature? Delete the file above\n"
                "--"
            )
            return True
        else:
            return False


if __name__ == "__main__":
    main()
