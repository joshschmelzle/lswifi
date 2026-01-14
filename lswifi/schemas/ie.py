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
lswifi.ie
~~~~~~~~~

schema definition for information element
"""


class InformationElement:
    """Base class for Information Elements"""

    def __init__(
        self,
        element,
        element_id,
        element_id_extension=None,
        extensible=None,
        fragmentable=None,
    ):
        self.element = element
        self.element_id = element_id
        self.element_id_extension = element_id_extension
        self.extensible = extensible
        self.fragmentable = fragmentable
