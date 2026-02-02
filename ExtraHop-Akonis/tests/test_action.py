"""Tests for ExtraHop base action class."""

import pytest
from unittest.mock import MagicMock, patch

from extrahop.action import ExtraHopAction
from extrahop.client.http_client import ExtraHopClient


class ConcreteExtraHopAction(ExtraHopAction):
    """Concrete implementation of ExtraHopAction for testing."""

    def run(self, arguments):
        """Implement abstract run method."""
        pass


class TestExtraHopAction:
    """Tests for ExtraHopAction base class."""

    @pytest.fixture
    def mock_action(self, mock_module_configuration):
        """Create mock action instance."""
        with patch.object(ConcreteExtraHopAction, "__init__", lambda x: None):
            action = ConcreteExtraHopAction()

            # Mock module with configuration
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]

            return action

    def test_client_property_creates_client(self, mock_action):
        """Test that client property creates ExtraHopClient."""
        client = mock_action.client

        assert isinstance(client, ExtraHopClient)
        assert client.hostname == "extrahop.example.com"
        assert client.api_key == "test-api-key-12345"
        assert client.verify_ssl is True

    def test_client_property_caches_client(self, mock_action):
        """Test that client property returns cached instance."""
        client1 = mock_action.client
        client2 = mock_action.client

        assert client1 is client2

    def test_client_with_ssl_disabled(self, mock_module_configuration):
        """Test client creation with SSL verification disabled."""
        with patch.object(ConcreteExtraHopAction, "__init__", lambda x: None):
            action = ConcreteExtraHopAction()
            action.module = MagicMock()
            action.module.configuration.hostname = mock_module_configuration["hostname"]
            action.module.configuration.api_key = mock_module_configuration["api_key"]
            action.module.configuration.verify_ssl = False

            client = action.client
            assert client.verify_ssl is False
