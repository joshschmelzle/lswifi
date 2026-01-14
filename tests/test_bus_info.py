"""Tests for bus information detection functions."""

import json
from unittest.mock import MagicMock, patch

import pytest

from lswifi.client import _get_usb_speed_from_pnp, get_adapter_bus_info


class TestGetAdapterBusInfo:
    """Tests for get_adapter_bus_info function."""

    @patch("lswifi.client.subprocess.run")
    def test_pcie_adapter(self, mock_run):
        """Test PCIe adapter detection with speed and width."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "PciExpressCurrentLinkSpeedEncoded": 3,
            "PciExpressCurrentLinkWidth": 1,
        })
        mock_run.return_value = mock_result

        bus_type, bus_info = get_adapter_bus_info("test-guid-1234")

        assert bus_type == "PCIe"
        assert bus_info == "8.0 GT/s x1"

    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_superspeed_via_location_path(self, mock_run):
        """Test USB 3.0 SuperSpeed adapter detection via location path."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps({
            "PnpDeviceId": "USB\\VID_0E8D&PID_7961\\000000000"
        })

        mock_result_3 = MagicMock()
        mock_result_3.returncode = 0
        mock_result_3.stdout = "3"

        mock_run.side_effect = [mock_result_1, mock_result_2, mock_result_3]

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb")

        assert bus_type == "USB"
        assert bus_info == "SuperSpeed (USB 3.0)"

    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_highspeed_via_location_path(self, mock_run):
        """Test USB 2.0 High-Speed adapter detection via location path."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps({
            "PnpDeviceId": "USB\\VID_1234&PID_5678\\SERIAL"
        })

        mock_result_3 = MagicMock()
        mock_result_3.returncode = 0
        mock_result_3.stdout = "2"

        mock_run.side_effect = [mock_result_1, mock_result_2, mock_result_3]

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb-hs")

        assert bus_type == "USB"
        assert bus_info == "High Speed (USB 2.0)"

    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_no_location_path(self, mock_run):
        """Test USB adapter when location path is not available."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps({
            "PnpDeviceId": "USB\\VID_ABCD&PID_EFGH\\NOSPEED"
        })

        mock_result_3 = MagicMock()
        mock_result_3.returncode = 0
        mock_result_3.stdout = ""

        mock_run.side_effect = [mock_result_1, mock_result_2, mock_result_3]

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb-no-speed")

        assert bus_type == "USB"
        assert bus_info is None

    @patch("lswifi.client.subprocess.run")
    def test_pci_adapter(self, mock_run):
        """Test PCI (non-Express) adapter detection."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps({"PnpDeviceId": "PCI\\VEN_8086&DEV_1234"})

        mock_run.side_effect = [mock_result_1, mock_result_2]

        bus_type, bus_info = get_adapter_bus_info("test-guid-pci")

        assert bus_type == "PCI"
        assert bus_info is None

    @patch("lswifi.client.subprocess.run")
    def test_no_adapter_found(self, mock_run):
        """Test when adapter is not found."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        bus_type, bus_info = get_adapter_bus_info("invalid-guid")

        assert bus_type is None
        assert bus_info is None

    @patch("lswifi.client.subprocess.run")
    def test_powershell_error(self, mock_run):
        """Test handling of PowerShell execution errors."""
        mock_run.side_effect = Exception("PowerShell error")

        bus_type, bus_info = get_adapter_bus_info("test-guid")

        assert bus_type is None
        assert bus_info is None


class TestGetUsbSpeedFromPnp:
    """Tests for _get_usb_speed_from_pnp function."""

    @patch("lswifi.client.subprocess.run")
    def test_superspeed_usb_3(self, mock_run):
        """Test SuperSpeed USB 3.0 detection from location path."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "3"
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_0E8D&PID_7961\\000000000")

        assert speed == 3

    @patch("lswifi.client.subprocess.run")
    def test_high_speed_usb_2(self, mock_run):
        """Test High-Speed USB 2.0 detection from location path."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "2"
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_1234&PID_5678\\SERIAL123")

        assert speed == 2

    @patch("lswifi.client.subprocess.run")
    def test_full_speed_usb_1_1(self, mock_run):
        """Test Full-Speed USB 1.1 detection from location path."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1"
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_ABCD&PID_EFGH\\TEST")

        assert speed == 1

    @patch("lswifi.client.subprocess.run")
    def test_low_speed_usb_1_1(self, mock_run):
        """Test Low-Speed USB 1.1 detection from location path."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "0"
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_0000&PID_0001\\LOW")

        assert speed == 0

    @patch("lswifi.client.subprocess.run")
    def test_no_location_path(self, mock_run):
        """Test when device has no location path."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_1111&PID_2222\\NOLOC")

        assert speed is None

    @patch("lswifi.client.subprocess.run")
    def test_powershell_error(self, mock_run):
        """Test handling of PowerShell execution errors."""
        mock_run.side_effect = Exception("PowerShell error")

        speed = _get_usb_speed_from_pnp("USB\\VID_ERR&PID_ERR\\ERROR")

        assert speed is None

    @patch("lswifi.client.subprocess.run")
    def test_invalid_output(self, mock_run):
        """Test handling of invalid PowerShell output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid"
        mock_run.return_value = mock_result

        speed = _get_usb_speed_from_pnp("USB\\VID_BAD&PID_DATA\\INVALID")

        assert speed is None
