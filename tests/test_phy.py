# -*- encoding: utf-8

from lswifi.schemas.phy import PHYType


class TestPHYType:
    """Test PHYType with the PHY names a backend can report."""

    def test_phy_eht(self):
        phy = PHYType("EHT")
        assert phy.amendment == "be"
        assert phy.generation == "7"
        assert str(phy) == "be"
        assert phy.name == "EHT"
        assert repr(phy) == "EHT"

    def test_phy_he(self):
        phy = PHYType("HE")
        assert phy.amendment == "ax"
        assert phy.generation == "6"

    def test_phy_vht(self):
        phy = PHYType("VHT")
        assert phy.amendment == "ac"
        assert phy.generation == "5"

    def test_phy_ht(self):
        phy = PHYType("HT")
        assert phy.amendment == "n"
        assert phy.generation == "4"

    def test_phy_erp(self):
        phy = PHYType("ERP")
        assert phy.amendment == "g"
        assert phy.generation == "3"

    def test_phy_hrdsss(self):
        phy = PHYType("HR-DSSS")
        assert phy.amendment == "b"
        assert phy.generation == "2"

    def test_phy_ofdm(self):
        phy = PHYType("OFDM")
        assert phy.amendment == "a"
        assert phy.generation == "1"

    def test_phy_unknown(self):
        phy = PHYType("UNKNOWN")
        assert phy.amendment == ""
        assert phy.generation == "-"

    def test_phy_windows_dict_value(self):
        """Windows DOT11_PHY_TYPE_DICT values keep today's blank amendment."""
        phy = PHYType("HT (802.11n)")
        assert phy.name == "HT (802.11n)"
        assert phy.amendment == ""

    def test_phy_none(self):
        """A backend without a PHY enum leaves the column blank."""
        phy = PHYType(None)
        assert phy.name == ""
        assert phy.amendment == ""
        assert phy.generation == "-"
        assert str(phy.out()) == ""

    def test_phy_out(self):
        phy = PHYType("HE")
        result = phy.out()
        assert str(result) == "ax"

    def test_phy_name_setter(self):
        phy = PHYType("HE")
        phy.name = "VHT"
        assert phy.name == "VHT"
        assert phy.amendment == "ac"
