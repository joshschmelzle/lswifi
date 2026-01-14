# -*- encoding: utf-8

import pytest

from lswifi.schemas.ie import InformationElement
from lswifi.schemas.out import (
    Alignment,
    Header,
    SubHeader,
    OUT_TUPLE,
    OutObject,
    OutList,
)
from lswifi.schemas.modes import Modes
from lswifi.schemas.encryption import Encryption
from lswifi.schemas.pmf import PMF


class TestInformationElement:
    def test_init_minimal(self):
        """Test basic initialization with required params."""
        ie = InformationElement(element=b"\x00\x01", element_id=0)
        assert ie.element == b"\x00\x01"
        assert ie.element_id == 0
        assert ie.element_id_extension is None
        assert ie.extensible is None
        assert ie.fragmentable is None

    def test_init_full(self):
        """Test initialization with all parameters."""
        ie = InformationElement(
            element=b"\xff",
            element_id=255,
            element_id_extension=35,
            extensible=True,
            fragmentable=False,
        )
        assert ie.element == b"\xff"
        assert ie.element_id == 255
        assert ie.element_id_extension == 35
        assert ie.extensible is True
        assert ie.fragmentable is False


class TestOutClasses:
    def test_alignment_enum(self):
        assert Alignment.LEFT.value == "<"
        assert Alignment.RIGHT.value == ">"
        assert Alignment.CENTER.value == "^"
        assert Alignment.NONE.value == ""

    def test_subheader(self):
        sh = SubHeader("test")
        assert str(sh) == "test"
        assert repr(sh) == "test"
        assert len(sh) == 4
        assert f"{sh:>10}" == "      test"

    def test_header(self):
        h = Header("TEST")
        assert str(h) == "TEST"
        assert repr(h) == "TEST"
        assert len(h) == 4
        assert h.alignment == Alignment.NONE

    def test_header_with_alignment(self):
        h = Header("TEST", Alignment.LEFT)
        assert h.alignment == Alignment.LEFT

    def test_out_tuple(self):
        ot = OUT_TUPLE("value", Header("H"), SubHeader("S"))
        assert str(ot) == "value"
        assert len(ot) == 5
        assert "OUT_TUPLE" in repr(ot)

    def test_out_object(self):
        obj = OutObject(value="test", header="HDR", subheader="sub")
        assert str(obj) == "test"
        assert obj.value == "test"
        assert repr(obj) == "test"
        assert len(obj) == 4

    def test_out_object_value_setter(self):
        obj = OutObject()
        obj.value = "new_value"
        assert obj.value == "new_value"

    def test_out_object_out(self):
        obj = OutObject(value="test", header="HDR", subheader="sub")
        result = obj.out()
        assert isinstance(result, OUT_TUPLE)
        assert str(result) == "test"

    def test_out_list(self):
        ol = OutList("a", "b", "c", header="HDR", subheader="sub")
        assert len(ol) == 3
        assert "a" in ol
        assert str(ol) == "a/b/c"

    def test_out_list_int_sorting(self):
        ol = OutList(3, 1, 2)
        assert str(ol) == "1/2/3"

    def test_out_list_insert(self):
        ol = OutList()
        ol.insert(0, "x")
        assert "x" in ol

    def test_out_list_setitem(self):
        ol = OutList("a", "b")
        ol[0] = "z"
        assert ol.elements[0] == "z"

    def test_out_list_iter(self):
        ol = OutList("a", "b")
        items = list(ol)
        assert items == ["a", "b"]

    def test_out_list_out(self):
        ol = OutList("a", header="H", subheader="S")
        result = ol.out()
        assert isinstance(result, OUT_TUPLE)


class TestModes:
    def test_modes_init(self):
        m = Modes("a", "b", "g", header="MODES", subheader="sub")
        assert len(m) == 3
        assert "a" in m

    def test_modes_str_ordering(self):
        """Modes should include recognized modes in defined order."""
        m = Modes("n", "a", "g", "b")
        result = str(m)
        # The order dict filters to known modes and joins them
        assert "a" in result
        assert "b" in result
        assert "g" in result
        assert "n" in result

    def test_modes_insert(self):
        m = Modes()
        m.insert(0, "ax")
        assert "ax" in m

    def test_modes_setitem(self):
        m = Modes("a", "b")
        m[0] = "g"
        assert m.elements[0] == "g"

    def test_modes_iter(self):
        m = Modes("a", "b")
        items = list(m)
        assert items == ["a", "b"]

    def test_modes_out(self):
        m = Modes("a", header="H", subheader="S")
        result = m.out()
        assert isinstance(result, OUT_TUPLE)


class TestEncryption:
    def test_encryption_init(self):
        e = Encryption()
        assert e.value == "NONE"
        assert str(e.header) == "ENCRYPTION"

    def test_encryption_format(self):
        e = Encryption()
        assert f"{e:>10}" == "      NONE"


class TestPMF:
    def test_pmf_init(self):
        p = PMF()
        assert p.value == "Disabled"
        assert str(p.header) == "PMF"

    def test_pmf_format(self):
        p = PMF()
        assert f"{p:>10}" == "  Disabled"
