# -*- coding: utf-8 -*-

"""
lswifi.lswifi
~~~~~~~~~

a CLI Wi-Fi scanning utility for Windows that leverages Microsofts Native Wifi wlanapi.h
"""

import asyncio
import logging
import os
import platform
import sys

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
from . import appsetup, core
from .__version__ import __title__
from .constants import APNAMEACKFILE, APNAMEJSONFILE


def app_path() -> None:
    appdata_path = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    path_exists = os.path.isdir(appdata_path)
    if not path_exists:
        os.mkdir(appdata_path)
    print(f"{appdata_path}")


def main():
    is_apname_ack_stored = False
    parser = appsetup.setup_parser()
    args = parser.parse_args()
    log = appsetup.setup_logger(args)
    log.debug(f"args {args}")
    log.debug(f"{sys.version}")
    if args.data_location:
        app_path()
        sys.exit()
    if args.apnames:
        is_apname_ack_stored = user_ack_apnames_disclaimer()
        log.debug(
            f"is there a stored ack for caching apnames on local machine? ({is_apname_ack_stored})"
        )

    loop = asyncio.get_event_loop()

    main_task = asyncio.ensure_future(core.scan(args, storedack=is_apname_ack_stored))

    try:
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        log.warning("caught KeyboardInterrupt... stopping...")
    except SystemExit:
        pass
    finally:
        loop.close()


def user_ack_apnames_disclaimer() -> bool:
    """retrieve ack from user that BSSIDs and discovered apnames will be cached in appdata"""
    logger = logging.getLogger(__name__)
    if os.getenv("LOCALAPPDATA"):
        appdata_folder = os.path.join(os.getenv("LOCALAPPDATA"), __title__)
    else:
        raise OSError
    is_path = os.path.isdir(appdata_folder)
    if not is_path:
        os.mkdir(appdata_folder)
        logger.debug("%s created? %s", appdata_folder, os.path.isdir(appdata_folder))
    ack = os.path.join(appdata_folder, APNAMEACKFILE)
    apnames = os.path.join(appdata_folder, APNAMEJSONFILE)
    if os.path.isfile(ack):
        return True
    else:
        print(
            "---\n"
            "AP (Access Point) names are not contained in every scan result.\n\n"
            "What?\n"
            "  - This feature locally caches BSSIDs and any detected corresponding AP names.\n"
            "  - Caching this information helps to more consistently provide AP names in output.\n"
            "Why?\n"
            "  - AP names are typically identified in beacon frames.\n"
            "  - Dwell time varies per channel meaning it could be less than the beacon interval.\n"
            "  - Retrieved scan results are a combination of beacons, probe responses, or sometimes a merged frame.\n"
            "Where?\n"
            "  - Data is stored and read from a JSON file on your local device here:\n\n"
            f"{apnames}\n"
            "---\n"
        )
        text = input("Do you want to enable this feature? yes/no: ")
        if "y" in text.lower()[:1]:
            with open(ack, "w") as file:
                pass  # we only need a placeholder file
            print(
                "---\n"
                "This feature has been enabled and your response stored here: \n\n"
                f"{ack}\n\n"
                "Want to disable this feature? Delete the file above\n"
                "---"
            )
            return True
        else:
            return False


if __name__ == "__main__":
    main()
