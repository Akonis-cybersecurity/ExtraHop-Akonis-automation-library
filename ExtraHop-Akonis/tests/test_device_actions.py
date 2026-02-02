"""Tests for ExtraHop device actions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from extrahop.device_actions import (
    GetDeviceAction,
    SearchDevicesAction,
    SearchRecordsAction,
)
from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopNotFoundError,
)


class TestGetDeviceAction:
    """Tests for GetDeviceAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(GetDeviceAction, "__init__", lambda x: None):
            action = GetDeviceAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_get_device_success(self, mock_action, sample_device):
        """Test successful device retrieval."""
        mock_client = MagicMock()
        mock_client.get_device = AsyncMock(return_value=sample_device)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "device_id": 5678,
            })

        assert result["success"] is True
        assert result["device"]["id"] == 5678
        assert result["device"]["display_name"] == "WORKSTATION-01"

    def test_get_device_not_found(self, mock_action):
        """Test retrieval of non-existent device."""
        mock_client = MagicMock()
        mock_client.get_device = AsyncMock(
            side_effect=ExtraHopNotFoundError("Device not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "device_id": 99999,
            })

        assert result["success"] is False
        assert "not found" in result["error"]
        mock_action.error.assert_called()

    def test_get_device_auth_error(self, mock_action):
        """Test retrieval with authentication error."""
        mock_client = MagicMock()
        mock_client.get_device = AsyncMock(
            side_effect=ExtraHopAuthError("Invalid API key", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "device_id": 5678,
            })

        assert result["success"] is False

    def test_get_device_api_error(self, mock_action):
        """Test retrieval with API error."""
        mock_client = MagicMock()
        mock_client.get_device = AsyncMock(
            side_effect=ExtraHopAPIError("Server error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "device_id": 5678,
            })

        assert result["success"] is False


class TestSearchDevicesAction:
    """Tests for SearchDevicesAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(SearchDevicesAction, "__init__", lambda x: None):
            action = SearchDevicesAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_search_devices_by_ip(self, mock_action, sample_device):
        """Test search devices by IP address."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(return_value=[sample_device])

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "ip_address": "192.168.1.100",
            })

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["devices"]) == 1

    def test_search_devices_by_hostname(self, mock_action, sample_device):
        """Test search devices by hostname."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(return_value=[sample_device])

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "hostname": "WORKSTATION-01",
            })

        assert result["success"] is True
        assert result["count"] == 1

    def test_search_devices_by_mac(self, mock_action, sample_device):
        """Test search devices by MAC address."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(return_value=[sample_device])

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "mac_address": "00:1A:2B:3C:4D:5E",
            })

        assert result["success"] is True
        assert result["count"] == 1

    def test_search_devices_with_limit(self, mock_action, sample_device):
        """Test search devices with custom limit."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(return_value=[sample_device] * 50)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "ip_address": "192.168.1.0",
                "limit": 50,
            })

        assert result["success"] is True
        assert result["count"] == 50

    def test_search_devices_no_criteria(self, mock_action):
        """Test search devices without any criteria."""
        result = mock_action.run({})

        assert result["success"] is False
        assert "criteria" in result["error"].lower()
        mock_action.error.assert_called()

    def test_search_devices_empty_result(self, mock_action):
        """Test search devices with no results."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(return_value=[])

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "ip_address": "10.0.0.1",
            })

        assert result["success"] is True
        assert result["count"] == 0
        assert result["devices"] == []

    def test_search_devices_auth_error(self, mock_action):
        """Test search with auth error."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(
            side_effect=ExtraHopAuthError("Forbidden", 403)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "ip_address": "192.168.1.100",
            })

        assert result["success"] is False

    def test_search_devices_api_error(self, mock_action):
        """Test search with API error."""
        mock_client = MagicMock()
        mock_client.search_devices = AsyncMock(
            side_effect=ExtraHopAPIError("Internal error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "ip_address": "192.168.1.100",
            })

        assert result["success"] is False


class TestSearchRecordsAction:
    """Tests for SearchRecordsAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(SearchRecordsAction, "__init__", lambda x: None):
            action = SearchRecordsAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_search_records_success(self, mock_action):
        """Test successful records search."""
        sample_records = [
            {"id": 1, "type": "http", "server": "example.com"},
            {"id": 2, "type": "http", "server": "test.com"},
        ]
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(return_value=sample_records)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
            })

        assert result["success"] is True
        assert result["count"] == 2

    def test_search_records_with_types(self, mock_action):
        """Test records search with specific types."""
        sample_records = [{"id": 1, "type": "dns"}]
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(return_value=sample_records)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
                "record_types": ["~dns", "~http"],
            })

        assert result["success"] is True

    def test_search_records_with_ip_filter(self, mock_action):
        """Test records search with IP filter."""
        sample_records = [{"id": 1, "ipaddr": "192.168.1.100"}]
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(return_value=sample_records)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
                "ip_address": "192.168.1.100",
            })

        assert result["success"] is True

    def test_search_records_with_limit(self, mock_action):
        """Test records search with custom limit."""
        sample_records = [{"id": i} for i in range(500)]
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(return_value=sample_records)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
                "limit": 500,
            })

        assert result["success"] is True
        assert result["count"] == 500

    def test_search_records_empty_result(self, mock_action):
        """Test records search with no results."""
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(return_value=[])

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
            })

        assert result["success"] is True
        assert result["count"] == 0

    def test_search_records_auth_error(self, mock_action):
        """Test records search with auth error."""
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(
            side_effect=ExtraHopAuthError("Unauthorized", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
            })

        assert result["success"] is False

    def test_search_records_api_error(self, mock_action):
        """Test records search with API error."""
        mock_client = MagicMock()
        mock_client.search_records = AsyncMock(
            side_effect=ExtraHopAPIError("Server error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "from_time": 1704067200000,
                "until_time": 1704153600000,
            })

        assert result["success"] is False
