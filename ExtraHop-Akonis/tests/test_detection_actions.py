"""Tests for ExtraHop detection actions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from extrahop.detection_actions import (
    UpdateDetectionStatusAction,
    AssignDetectionAction,
    CloseDetectionAction,
    AcknowledgeDetectionAction,
    LinkTicketToDetectionAction,
    GetDetectionAction,
)
from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopNotFoundError,
)


class TestUpdateDetectionStatusAction:
    """Tests for UpdateDetectionStatusAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(UpdateDetectionStatusAction, "__init__", lambda x: None):
            action = UpdateDetectionStatusAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_update_status_success(self, mock_action, sample_detection):
        """Test successful status update."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "status": "in_progress",
            })

        assert result["success"] is True
        assert result["detection"]["id"] == 12345
        mock_action.log.assert_called()

    def test_update_status_not_found(self, mock_action):
        """Test status update with non-existent detection."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Detection not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
                "status": "closed",
            })

        assert result["success"] is False
        assert "not found" in result["error"]
        mock_action.error.assert_called()

    def test_update_status_auth_error(self, mock_action):
        """Test status update with authentication error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Invalid API key", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "status": "closed",
            })

        assert result["success"] is False
        assert "error" in result

    def test_update_status_api_error(self, mock_action):
        """Test status update with API error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAPIError("Server error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "status": "closed",
            })

        assert result["success"] is False


class TestAssignDetectionAction:
    """Tests for AssignDetectionAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(AssignDetectionAction, "__init__", lambda x: None):
            action = AssignDetectionAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_assign_detection_success(self, mock_action, sample_detection):
        """Test successful detection assignment."""
        sample_detection["assignee"] = "security_analyst"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "assignee": "security_analyst",
            })

        assert result["success"] is True
        assert result["detection"]["assignee"] == "security_analyst"

    def test_assign_detection_not_found(self, mock_action):
        """Test assignment with non-existent detection."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Detection not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
                "assignee": "analyst",
            })

        assert result["success"] is False

    def test_assign_detection_auth_error(self, mock_action):
        """Test assignment with auth error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Forbidden", 403)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "assignee": "analyst",
            })

        assert result["success"] is False

    def test_assign_detection_api_error(self, mock_action):
        """Test assignment with API error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAPIError("Internal error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "assignee": "analyst",
            })

        assert result["success"] is False


class TestCloseDetectionAction:
    """Tests for CloseDetectionAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(CloseDetectionAction, "__init__", lambda x: None):
            action = CloseDetectionAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_close_detection_success(self, mock_action, sample_detection):
        """Test successful detection closure."""
        sample_detection["status"] = "closed"
        sample_detection["resolution"] = "action_taken"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "resolution": "action_taken",
            })

        assert result["success"] is True
        assert result["detection"]["status"] == "closed"

    def test_close_detection_default_resolution(self, mock_action, sample_detection):
        """Test closure with default resolution."""
        sample_detection["status"] = "closed"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is True
        # Should use default resolution
        mock_client.update_detection.assert_called_once()

    def test_close_detection_not_found(self, mock_action):
        """Test closure with non-existent detection."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
            })

        assert result["success"] is False

    def test_close_detection_auth_error(self, mock_action):
        """Test closure with auth error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Unauthorized", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False

    def test_close_detection_api_error(self, mock_action):
        """Test closure with API error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAPIError("Error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False


class TestAcknowledgeDetectionAction:
    """Tests for AcknowledgeDetectionAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(AcknowledgeDetectionAction, "__init__", lambda x: None):
            action = AcknowledgeDetectionAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_acknowledge_success(self, mock_action, sample_detection):
        """Test successful acknowledgment."""
        sample_detection["status"] = "acknowledged"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is True

    def test_acknowledge_not_found(self, mock_action):
        """Test acknowledgment with non-existent detection."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
            })

        assert result["success"] is False

    def test_acknowledge_auth_error(self, mock_action):
        """Test acknowledgment with auth error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Auth error", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False

    def test_acknowledge_api_error(self, mock_action):
        """Test acknowledgment with API error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAPIError("API error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False


class TestLinkTicketToDetectionAction:
    """Tests for LinkTicketToDetectionAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(LinkTicketToDetectionAction, "__init__", lambda x: None):
            action = LinkTicketToDetectionAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_link_ticket_success(self, mock_action, sample_detection):
        """Test successful ticket linking."""
        sample_detection["ticket_id"] = "INC0012345"
        sample_detection["ticket_url"] = "https://snow.example.com/INC0012345"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "ticket_id": "INC0012345",
                "ticket_url": "https://snow.example.com/INC0012345",
            })

        assert result["success"] is True
        assert result["detection"]["ticket_id"] == "INC0012345"

    def test_link_ticket_without_url(self, mock_action, sample_detection):
        """Test ticket linking without URL."""
        sample_detection["ticket_id"] = "INC0012345"
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "ticket_id": "INC0012345",
            })

        assert result["success"] is True

    def test_link_ticket_with_empty_url(self, mock_action, sample_detection):
        """Test ticket linking with empty URL."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "ticket_id": "INC0012345",
                "ticket_url": "",
            })

        assert result["success"] is True

    def test_link_ticket_not_found(self, mock_action):
        """Test ticket linking with non-existent detection."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
                "ticket_id": "INC0012345",
            })

        assert result["success"] is False

    def test_link_ticket_auth_error(self, mock_action):
        """Test ticket linking with auth error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Auth error", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "ticket_id": "INC0012345",
            })

        assert result["success"] is False

    def test_link_ticket_api_error(self, mock_action):
        """Test ticket linking with API error."""
        mock_client = MagicMock()
        mock_client.update_detection = AsyncMock(
            side_effect=ExtraHopAPIError("API error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
                "ticket_id": "INC0012345",
            })

        assert result["success"] is False


class TestGetDetectionAction:
    """Tests for GetDetectionAction."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(GetDetectionAction, "__init__", lambda x: None):
            action = GetDetectionAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            action.log = MagicMock()
            action.error = MagicMock()
            return action

    def test_get_detection_success(self, mock_action, sample_detection):
        """Test successful detection retrieval."""
        mock_client = MagicMock()
        mock_client.get_detection = AsyncMock(return_value=sample_detection)

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is True
        assert result["detection"]["id"] == 12345
        assert result["detection"]["type"] == "lateral_movement_smb"

    def test_get_detection_not_found(self, mock_action):
        """Test retrieval of non-existent detection."""
        mock_client = MagicMock()
        mock_client.get_detection = AsyncMock(
            side_effect=ExtraHopNotFoundError("Not found", 404)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 99999,
            })

        assert result["success"] is False
        mock_action.error.assert_called()

    def test_get_detection_auth_error(self, mock_action):
        """Test retrieval with auth error."""
        mock_client = MagicMock()
        mock_client.get_detection = AsyncMock(
            side_effect=ExtraHopAuthError("Auth error", 401)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False

    def test_get_detection_api_error(self, mock_action):
        """Test retrieval with API error."""
        mock_client = MagicMock()
        mock_client.get_detection = AsyncMock(
            side_effect=ExtraHopAPIError("Server error", 500)
        )

        with patch.object(mock_action, "client", mock_client):
            result = mock_action.run({
                "detection_id": 12345,
            })

        assert result["success"] is False
