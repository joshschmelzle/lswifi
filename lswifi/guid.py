#
# Extracted from from comtypes.py

import functools
import sys
from ctypes import (
    Structure,
    byref,
    c_byte,
    c_ulong,
    c_ushort,
    c_wchar_p,
)

BYTE = c_byte
WORD = c_ushort
DWORD = c_ulong


@functools.cache
def _ole32():
    """Load the ole32 GUID helpers on first use, not at import"""
    if sys.platform != "win32":
        raise OSError("GUID string conversion requires ole32 (Windows only)")
    from ctypes import oledll, windll

    return (
        oledll.ole32.CLSIDFromString,
        oledll.ole32.StringFromCLSID,
        windll.ole32.CoTaskMemFree,
    )


class GUID(Structure):
    _fields_ = [("Data1", DWORD), ("Data2", WORD), ("Data3", WORD), ("Data4", BYTE * 8)]

    def __init__(self, name=None):
        if name is not None:
            _CLSIDFromString, _, _ = _ole32()
            _CLSIDFromString(str(name), byref(self))

    def __repr__(self):
        return f'GUID("{self}")'

    def __unicode__(self):
        _, _StringFromCLSID, _CoTaskMemFree = _ole32()
        p = c_wchar_p()
        _StringFromCLSID(byref(self), byref(p))
        result = p.value
        _CoTaskMemFree(p)
        return result

    __str__ = __unicode__
