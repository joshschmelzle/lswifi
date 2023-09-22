# -*- coding: utf-8 -*-

"""
lswifi.syslog
~~~~~~~~~~~~~

define syslog bits
"""

import socket
from datetime import datetime

SYSLOG_SERVERS = []

# Log level mapping
SYSLOG_LEVEL = {
    "ALERT": "1",
    "CRITICAL": "2",
    "ERROR": "3",
    "WARN": "4",
    "NOTICE": "5",
    "INFO": "6",
    "DEBUG": "7",
}

# Set log level
LOG_LEVEL = SYSLOG_LEVEL["DEBUG"]

SYSLOG_SOCKET = sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP


# Send syslog messages
def message(message, level):
    if LOG_LEVEL >= SYSLOG_LEVEL[level]:
        if SYSLOG_SERVERS:
            for ip in SYSLOG_SERVERS:
                line_to_send = (
                    "<"
                    + SYSLOG_LEVEL[level]
                    + "> "
                    + datetime.now().strftime("%b %d %H:%M:%S")
                    + ", Client: "
                    + message
                )
                try:
                    SYSLOG_SOCKET.sendto(bytes(line_to_send, "utf-8"), (ip, 514))
                except socket.error:
                    pass
