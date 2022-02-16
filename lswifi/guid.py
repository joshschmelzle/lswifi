# extracted from from comtypes.py

from ctypes import (
    Structure,
    byref,
    c_byte,
    c_ulong,
    c_ushort,
    c_wchar_p,
    oledll,
    windll,
)

BYTE = c_byte
WORD = c_ushort
DWORD = c_ulong

_ole32 = oledll.ole32

_CLSIDFromString = _ole32.CLSIDFromString
_StringFromCLSID = _ole32.StringFromCLSID
_CoTaskMemFree = windll.ole32.CoTaskMemFree


class GUID(Structure):
    _fields_ = [("Data1", DWORD), ("Data2", WORD), ("Data3", WORD), ("Data4", BYTE * 8)]

    def __init__(self, name=None):
        if name is not None:
            _CLSIDFromString(str(name), byref(self))

    def __repr__(self):
        return 'GUID("%s")' % str(self)

    def __unicode__(self):
        p = c_wchar_p()
        _StringFromCLSID(byref(self), byref(p))
        result = p.value
        _CoTaskMemFree(p)
        return result

    __str__ = __unicode__
