"""Tests for bus information detection functions."""

import json
import struct
from unittest.mock import MagicMock, patch

from lswifi.client import (
    _get_usb_speed_from_pnp,
    _is_usb_device_present,
    _get_usb_parent_device,
    _query_usb_speed_ioctl,
    get_adapter_bus_info,
)


class TestIsUsbDevicePresent:
    """Tests for _is_usb_device_present function."""

    @patch("lswifi.client.subprocess.run")
    def test_device_present(self, mock_run):
        """Test when device is present."""
        mock_result = MagicMock()
        mock_result.stdout = "True"
        mock_run.return_value = mock_result

        assert _is_usb_device_present("USB\\VID_0E8D&PID_7961\\000000000") is True

    @patch("lswifi.client.subprocess.run")
    def test_device_not_present(self, mock_run):
        """Test when device is not present."""
        mock_result = MagicMock()
        mock_result.stdout = "False"
        mock_run.return_value = mock_result

        assert _is_usb_device_present("USB\\VID_0E8D&PID_7961\\000000000") is False

    @patch("lswifi.client.subprocess.run")
    def test_device_present_case_insensitive(self, mock_run):
        """Test case insensitive comparison."""
        mock_result = MagicMock()
        mock_result.stdout = "TRUE"
        mock_run.return_value = mock_result

        assert _is_usb_device_present("USB\\VID_0E8D&PID_7961\\000000000") is True

    @patch("lswifi.client.subprocess.run")
    def test_powershell_exception(self, mock_run):
        """Test handling of PowerShell exceptions."""
        mock_run.side_effect = Exception("PowerShell error")

        assert _is_usb_device_present("USB\\VID_0E8D&PID_7961\\000000000") is False


class TestGetUsbParentDevice:
    """Tests for _get_usb_parent_device function."""

    @patch("lswifi.client.subprocess.run")
    def test_get_parent_success(self, mock_run):
        """Test successful parent device retrieval."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "USB\\ROOT_HUB30\\5&e28ec11&0&0"
        mock_run.return_value = mock_result

        result = _get_usb_parent_device("USB\\VID_0E8D&PID_7961\\000000000")
        assert result == "USB\\ROOT_HUB30\\5&e28ec11&0&0"

    @patch("lswifi.client.subprocess.run")
    def test_get_parent_empty_output(self, mock_run):
        """Test when PowerShell returns empty output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = _get_usb_parent_device("USB\\VID_0E8D&PID_7961\\000000000")
        assert result is None

    @patch("lswifi.client.subprocess.run")
    def test_get_parent_exception(self, mock_run):
        """Test handling of exceptions."""
        mock_run.side_effect = Exception("PowerShell error")

        result = _get_usb_parent_device("USB\\VID_0E8D&PID_7961\\000000000")
        assert result is None


class TestQueryUsbSpeedIoctl:
    """Tests for _query_usb_speed_ioctl function."""

    @patch("lswifi.client._kernel32")
    def test_superspeed_plus(self, mock_kernel32):
        """Test SuperSpeed+ (USB 3.1+) detection."""
        mock_kernel32.CreateFileW.return_value = 123
        with patch("lswifi.client.ctypes.create_string_buffer") as mock_buffer:
            mock_buf = MagicMock()
            # flags=0x04 means DeviceIsOperatingAtSuperSpeedPlusOrHigher
            mock_buf.raw = struct.pack("<IIII", 1, 16, 0x07, 0x04)
            mock_buf.__len__ = lambda self: 16
            mock_buffer.return_value = mock_buf
            mock_kernel32.DeviceIoControl.return_value = True

            result = _query_usb_speed_ioctl("\\\\?\\USB#ROOT_HUB", 1)
            assert result == 4

    @patch("lswifi.client._kernel32")
    def test_superspeed(self, mock_kernel32):
        """Test SuperSpeed (USB 3.0) detection."""
        mock_kernel32.CreateFileW.return_value = 123
        with patch("lswifi.client.ctypes.create_string_buffer") as mock_buffer:
            mock_buf = MagicMock()
            # flags=0x01 means DeviceIsOperatingAtSuperSpeedOrHigher
            mock_buf.raw = struct.pack("<IIII", 1, 16, 0x07, 0x01)
            mock_buf.__len__ = lambda self: 16
            mock_buffer.return_value = mock_buf
            mock_kernel32.DeviceIoControl.return_value = True

            result = _query_usb_speed_ioctl("\\\\?\\USB#ROOT_HUB", 1)
            assert result == 3

    @patch("lswifi.client._kernel32")
    def test_highspeed(self, mock_kernel32):
        """Test High Speed (USB 2.0) detection."""
        mock_kernel32.CreateFileW.return_value = 123
        with patch("lswifi.client.ctypes.create_string_buffer") as mock_buffer:
            mock_buf = MagicMock()
            # flags=0x00 means not operating at SuperSpeed
            mock_buf.raw = struct.pack("<IIII", 1, 16, 0x03, 0x00)
            mock_buf.__len__ = lambda self: 16
            mock_buffer.return_value = mock_buf
            mock_kernel32.DeviceIoControl.return_value = True

            result = _query_usb_speed_ioctl("\\\\?\\USB#ROOT_HUB", 1)
            assert result == 2

    @patch("lswifi.client._kernel32")
    def test_invalid_handle(self, mock_kernel32):
        """Test handling of invalid handle from CreateFileW."""
        from lswifi.client import _INVALID_HANDLE_VALUE

        mock_kernel32.CreateFileW.return_value = _INVALID_HANDLE_VALUE
        with patch("lswifi.client.ctypes.GetLastError", return_value=5):
            result = _query_usb_speed_ioctl("\\\\?\\USB#ROOT_HUB", 1)
            assert result is None

    @patch("lswifi.client._kernel32")
    def test_ioctl_failure(self, mock_kernel32):
        """Test handling of DeviceIoControl failure."""
        mock_kernel32.CreateFileW.return_value = 123
        mock_kernel32.DeviceIoControl.return_value = False
        with patch("lswifi.client.ctypes.GetLastError", return_value=1):
            with patch("lswifi.client.ctypes.create_string_buffer") as mock_buffer:
                mock_buf = MagicMock()
                mock_buf.__len__ = lambda self: 16
                mock_buffer.return_value = mock_buf

                result = _query_usb_speed_ioctl("\\\\?\\USB#ROOT_HUB", 1)
                assert result is None


class TestGetUsbSpeedFromPnp:
    """Tests for _get_usb_speed_from_pnp function."""

    @patch("lswifi.client._query_usb_speed_ioctl")
    @patch("lswifi.client._get_usb_parent_device")
    @patch("lswifi.client.winreg.QueryValueEx")
    @patch("lswifi.client.winreg.OpenKey")
    @patch("lswifi.client._is_usb_device_present")
    def test_superspeed_usb_3(
        self, mock_present, mock_open, mock_query, mock_parent, mock_ioctl
    ):
        """Test SuperSpeed USB 3.0 detection."""
        mock_present.return_value = True
        mock_query.return_value = ("Port_#0001.Hub_#0004", None)
        mock_parent.return_value = "USB\\ROOT_HUB30\\5&e28ec11&0&0"
        mock_ioctl.return_value = 3

        speed = _get_usb_speed_from_pnp("USB\\VID_0E8D&PID_7961\\000000000")
        assert speed == 3

    @patch("lswifi.client._query_usb_speed_ioctl")
    @patch("lswifi.client._get_usb_parent_device")
    @patch("lswifi.client.winreg.QueryValueEx")
    @patch("lswifi.client.winreg.OpenKey")
    @patch("lswifi.client._is_usb_device_present")
    def test_high_speed_usb_2(
        self, mock_present, mock_open, mock_query, mock_parent, mock_ioctl
    ):
        """Test High-Speed USB 2.0 detection."""
        mock_present.return_value = True
        mock_query.return_value = ("Port_#0002.Hub_#0003", None)
        mock_parent.return_value = "USB\\ROOT_HUB30\\5&e28ec11&0&0"
        mock_ioctl.return_value = 2

        speed = _get_usb_speed_from_pnp("USB\\VID_1234&PID_5678\\SERIAL123")
        assert speed == 2

    @patch("lswifi.client._query_usb_speed_ioctl")
    @patch("lswifi.client._get_usb_parent_device")
    @patch("lswifi.client.winreg.QueryValueEx")
    @patch("lswifi.client.winreg.OpenKey")
    @patch("lswifi.client._is_usb_device_present")
    def test_superspeed_plus_usb_31(
        self, mock_present, mock_open, mock_query, mock_parent, mock_ioctl
    ):
        """Test SuperSpeed+ USB 3.1+ detection."""
        mock_present.return_value = True
        mock_query.return_value = ("Port_#0001.Hub_#0001", None)
        mock_parent.return_value = "USB\\ROOT_HUB31\\5&e28ec11&0&0"
        mock_ioctl.return_value = 4

        speed = _get_usb_speed_from_pnp("USB\\VID_ABCD&PID_EFGH\\TEST")
        assert speed == 4

    @patch("lswifi.client._is_usb_device_present")
    def test_device_not_present(self, mock_present):
        """Test when device is not present/connected."""
        mock_present.return_value = False

        speed = _get_usb_speed_from_pnp("USB\\VID_0E8D&PID_7961\\000000000")
        assert speed is None

    @patch("lswifi.client.winreg.OpenKey")
    @patch("lswifi.client._is_usb_device_present")
    def test_registry_error(self, mock_present, mock_open):
        """Test handling of registry errors."""
        mock_present.return_value = True
        mock_open.side_effect = FileNotFoundError("Registry key not found")

        speed = _get_usb_speed_from_pnp("USB\\VID_ERR&PID_ERR\\ERROR")
        assert speed is None

    @patch("lswifi.client._get_usb_parent_device")
    @patch("lswifi.client.winreg.QueryValueEx")
    @patch("lswifi.client.winreg.OpenKey")
    @patch("lswifi.client._is_usb_device_present")
    def test_no_parent_device(self, mock_present, mock_open, mock_query, mock_parent):
        """Test when parent device cannot be found."""
        mock_present.return_value = True
        mock_query.return_value = ("Port_#0001.Hub_#0001", None)
        mock_parent.return_value = None

        speed = _get_usb_speed_from_pnp("USB\\VID_1111&PID_2222\\NOLOC")
        assert speed is None


class TestGetAdapterBusInfo:
    """Tests for get_adapter_bus_info function."""

    @patch("lswifi.client.subprocess.run")
    def test_pcie_adapter(self, mock_run):
        """Test PCIe adapter detection with speed and width."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "PciExpressCurrentLinkSpeedEncoded": 3,
                "PciExpressCurrentLinkWidth": 1,
            }
        )
        mock_run.return_value = mock_result

        bus_type, bus_info = get_adapter_bus_info("test-guid-1234")

        assert bus_type == "PCIe"
        assert bus_info == "8.0 GT/s x1"

    @patch("lswifi.client._get_usb_speed_from_pnp")
    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_superspeed_via_ioctl(self, mock_run, mock_usb_speed):
        """Test USB 3.0 SuperSpeed adapter detection via IOCTL."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps(
            {"PnpDeviceId": "USB\\VID_0E8D&PID_7961\\000000000"}
        )

        mock_run.side_effect = [mock_result_1, mock_result_2]
        mock_usb_speed.return_value = 3

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb")

        assert bus_type == "USB"
        assert bus_info == "SuperSpeed (USB 3.0)"

    @patch("lswifi.client._get_usb_speed_from_pnp")
    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_highspeed_via_ioctl(self, mock_run, mock_usb_speed):
        """Test USB 2.0 High-Speed adapter detection via IOCTL."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps(
            {"PnpDeviceId": "USB\\VID_1234&PID_5678\\SERIAL"}
        )

        mock_run.side_effect = [mock_result_1, mock_result_2]
        mock_usb_speed.return_value = 2

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb-hs")

        assert bus_type == "USB"
        assert bus_info == "High Speed (USB 2.0)"

    @patch("lswifi.client._get_usb_speed_from_pnp")
    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_superspeed_plus_via_ioctl(self, mock_run, mock_usb_speed):
        """Test USB 3.1+ SuperSpeed+ adapter detection via IOCTL."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps(
            {"PnpDeviceId": "USB\\VID_ABCD&PID_EFGH\\FAST"}
        )

        mock_run.side_effect = [mock_result_1, mock_result_2]
        mock_usb_speed.return_value = 4

        bus_type, bus_info = get_adapter_bus_info("test-guid-usb-ss-plus")

        assert bus_type == "USB"
        assert bus_info == "SuperSpeed+ (USB 3.1+)"

    @patch("lswifi.client._get_usb_speed_from_pnp")
    @patch("lswifi.client.subprocess.run")
    def test_usb_adapter_no_speed_info(self, mock_run, mock_usb_speed):
        """Test USB adapter when speed cannot be determined."""
        mock_result_1 = MagicMock()
        mock_result_1.returncode = 0
        mock_result_1.stdout = "{}"

        mock_result_2 = MagicMock()
        mock_result_2.returncode = 0
        mock_result_2.stdout = json.dumps(
            {"PnpDeviceId": "USB\\VID_ABCD&PID_EFGH\\NOSPEED"}
        )

        mock_run.side_effect = [mock_result_1, mock_result_2]
        mock_usb_speed.return_value = None

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
