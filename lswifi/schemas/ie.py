# -*- coding: utf-8 -*-

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
