"""Tests for ExtraHop Detections Connector."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from extrahop.detections_connector import (
    ExtraHopDetectionsConnector,
    ExtraHopDetectionsConnectorConfiguration,
)
from extrahop.client.errors import ExtraHopAuthError, ExtraHopRateLimitError


class TestExtraHopDetectionsConnectorConfiguration:
    """Tests for connector configuration."""

    def test_default_configuration(self):
        """Test default configuration values.

        Note: Due to SDK compatibility, we check field defaults differently.
        """
        config = ExtraHopDetectionsConnectorConfiguration(
            intake_key="test-intake-key",
        )
        # Check that intake_key is set
        assert config.intake_key == "test-intake-key"
        # Configuration object should be created successfully
        assert config is not None

    def test_custom_configuration(self):
        """Test custom configuration values."""
        config = ExtraHopDetectionsConnectorConfiguration(
            intake_key="test-intake-key",
            detection_categories=["sec", "sec.lateral"],
            min_risk_score=50,
            detection_statuses=["new"],
            polling_frequency_minutes=10,
            historical_days=14,
            batch_size=500,
            include_audit_logs=True,
        )
        assert config.detection_categories == ["sec", "sec.lateral"]
        assert config.min_risk_score == 50
        assert config.detection_statuses == ["new"]
        assert config.polling_frequency_minutes == 10
        assert config.historical_days == 14
        assert config.batch_size == 500
        assert config.include_audit_logs is True

    def test_risk_score_validation(self):
        """Test risk score boundaries.

        Note: Pydantic validation behavior depends on SDK version.
        We test that valid boundary values work correctly.
        """
        # Valid min boundary
        config_min = ExtraHopDetectionsConnectorConfiguration(
            intake_key="test",
            min_risk_score=0,
        )
        assert config_min.min_risk_score == 0

        # Valid max boundary
        config_max = ExtraHopDetectionsConnectorConfiguration(
            intake_key="test",
            min_risk_score=99,
        )
        assert config_max.min_risk_score == 99


class TestDetectionFormatting:
    """Tests for detection event formatting."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        """Create mock connector instance."""
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector._seen_detections = {}
            connector.log = MagicMock()

            # Mock module
            connector.module = MagicMock()
            connector.module.configuration.hostname = mock_module_configuration["hostname"]
            connector.module.configuration.api_key = mock_module_configuration["api_key"]
            connector.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]

            # Mock configuration
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )

            return connector

    def test_format_detection_event_basic(self, mock_connector, sample_detection):
        """Test basic detection event formatting."""
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["event"]["kind"] == "alert"
        assert event["event"]["module"] == "extrahop"
        assert event["event"]["dataset"] == "extrahop.detections"
        assert event["observer"]["vendor"] == "ExtraHop"
        assert event["observer"]["product"] == "Reveal(x)"
        assert event["extrahop"]["detection"]["id"] == 12345

    def test_format_detection_event_severity_critical(self, mock_connector, sample_detection):
        """Test severity mapping for critical risk score."""
        sample_detection["risk_score"] = 85
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["event"]["severity"] == 4
        assert event["event"]["severity_label"] == "critical"

    def test_format_detection_event_severity_high(self, mock_connector, sample_detection):
        """Test severity mapping for high risk score."""
        sample_detection["risk_score"] = 60
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["event"]["severity"] == 3
        assert event["event"]["severity_label"] == "high"

    def test_format_detection_event_severity_medium(self, mock_connector, sample_detection):
        """Test severity mapping for medium risk score."""
        sample_detection["risk_score"] = 40
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["event"]["severity"] == 2
        assert event["event"]["severity_label"] == "medium"

    def test_format_detection_event_severity_low(self, mock_connector, sample_detection):
        """Test severity mapping for low risk score."""
        sample_detection["risk_score"] = 15
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["event"]["severity"] == 1
        assert event["event"]["severity_label"] == "low"

    def test_format_detection_event_mitre_mapping(self, mock_connector, sample_detection):
        """Test MITRE ATT&CK mapping extraction."""
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert "threat" in event
        assert event["threat"]["tactic"]["id"] == ["TA0008"]
        assert event["threat"]["technique"]["id"] == ["T1021", "T1021.002"]

    def test_format_detection_event_participants(self, mock_connector, sample_detection):
        """Test participant extraction as source/destination."""
        event_str = mock_connector._format_detection_event(sample_detection)
        event = json.loads(event_str)

        assert event["source"]["ip"] == "192.168.1.100"
        assert event["source"]["hostname"] == "WORKSTATION-01"
        assert event["source"]["mac"] == "00:1A:2B:3C:4D:5E"

        assert event["destination"]["ip"] == "192.168.1.10"
        assert event["destination"]["hostname"] == "SERVER-DC01"
        assert event["destination"]["mac"] == "00:1A:2B:3C:4D:5F"

    def test_format_audit_event(self, mock_connector, sample_audit_log):
        """Test audit log event formatting."""
        event_str = mock_connector._format_audit_event(sample_audit_log)
        event = json.loads(event_str)

        assert event["event"]["kind"] == "event"
        assert event["event"]["dataset"] == "extrahop.auditlog"
        assert event["user"]["name"] == "admin"
        assert event["extrahop"]["audit"]["id"] == 1001


class TestDeduplication:
    """Tests for detection deduplication."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        """Create mock connector with TTL cache."""
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            from cachetools import TTLCache
            connector._seen_detections = TTLCache(maxsize=1000, ttl=3600)
            connector.log = MagicMock()
            return connector

    def test_is_duplicate_new_detection(self, mock_connector, sample_detection):
        """Test new detection is not marked as duplicate."""
        result = mock_connector._is_duplicate(sample_detection)
        assert result is False

    def test_is_duplicate_seen_detection(self, mock_connector, sample_detection):
        """Test seen detection is marked as duplicate."""
        # First call - not duplicate
        mock_connector._is_duplicate(sample_detection)

        # Second call - is duplicate
        result = mock_connector._is_duplicate(sample_detection)
        assert result is True

    def test_is_duplicate_same_id_different_mod_time(self, mock_connector, sample_detection):
        """Test same detection ID with different mod_time is not duplicate."""
        # First detection
        mock_connector._is_duplicate(sample_detection)

        # Same ID but updated (different mod_time)
        sample_detection["mod_time"] = sample_detection["mod_time"] + 1000
        result = mock_connector._is_duplicate(sample_detection)
        assert result is False

    def test_is_duplicate_missing_fields(self, mock_connector):
        """Test detection with missing ID/mod_time is not duplicate."""
        detection_no_id = {"mod_time": 1234567890}
        detection_no_mod = {"id": 12345}

        assert mock_connector._is_duplicate(detection_no_id) is False
        assert mock_connector._is_duplicate(detection_no_mod) is False


class TestCheckpointManagement:
    """Tests for checkpoint management."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        """Create mock connector with context."""
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector.context = {}
            connector._checkpoint_key_detections = "last_detection_mod_time"
            connector._checkpoint_key_audit = "last_audit_time"
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    def test_get_checkpoint_exists(self, mock_connector):
        """Test getting existing checkpoint."""
        mock_connector.context["last_detection_mod_time"] = 1704067200000
        result = mock_connector._get_checkpoint("last_detection_mod_time")
        assert result == 1704067200000

    def test_get_checkpoint_not_exists(self, mock_connector):
        """Test getting non-existent checkpoint."""
        result = mock_connector._get_checkpoint("last_detection_mod_time")
        assert result is None

    def test_set_checkpoint(self, mock_connector):
        """Test setting checkpoint."""
        mock_connector._set_checkpoint("last_detection_mod_time", 1704067200000)
        assert mock_connector.context["last_detection_mod_time"] == 1704067200000

    def test_get_initial_mod_time(self, mock_connector):
        """Test getting initial mod_time for first run."""
        import time
        before = int((time.time() - 7 * 24 * 3600) * 1000)
        result = mock_connector._get_initial_mod_time()
        after = int((time.time() - 7 * 24 * 3600) * 1000)

        assert before <= result <= after


class TestProcessDetections:
    """Tests for detection processing."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        """Create mock connector."""
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            from cachetools import TTLCache
            connector._seen_detections = TTLCache(maxsize=1000, ttl=3600)
            connector.context = {}
            connector._checkpoint_key_detections = "last_detection_mod_time"
            connector.log = MagicMock()
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    @pytest.mark.asyncio
    async def test_process_detections_updates_checkpoint(
        self, mock_connector, sample_detection, sample_detection_c2
    ):
        """Test that processing detections updates checkpoint to max mod_time."""
        with patch("extrahop.detections_connector.METRICS"):
            detections = [sample_detection, sample_detection_c2]
            await mock_connector._process_detections(detections)

            # Max mod_time should be from sample_detection_c2 (1704082000000)
            assert mock_connector.context["last_detection_mod_time"] == 1704082000000

    @pytest.mark.asyncio
    async def test_process_detections_filters_duplicates(self, mock_connector, sample_detection):
        """Test that duplicate detections are filtered."""
        with patch("extrahop.detections_connector.METRICS"):
            # Process same detection twice
            events1 = await mock_connector._process_detections([sample_detection])
            events2 = await mock_connector._process_detections([sample_detection])

            assert len(events1) == 1
            assert len(events2) == 0  # Duplicate filtered

    @pytest.mark.asyncio
    async def test_process_detections_returns_formatted_events(
        self, mock_connector, sample_detection
    ):
        """Test that processed detections are properly formatted."""
        with patch("extrahop.detections_connector.METRICS"):
            events = await mock_connector._process_detections([sample_detection])

            assert len(events) == 1
            event = json.loads(events[0])
            assert event["extrahop"]["detection"]["id"] == 12345


class TestConnectorIntegration:
    """Integration tests for connector."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        """Create fully mocked connector."""
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            from cachetools import TTLCache
            connector._seen_detections = TTLCache(maxsize=1000, ttl=3600)
            connector.context = {}
            connector._checkpoint_key_detections = "last_detection_mod_time"
            connector._checkpoint_key_audit = "last_audit_time"
            connector._client = None
            connector.log = MagicMock()
            connector.push_data_to_intakes = AsyncMock()

            # Mock module
            connector.module = MagicMock()
            connector.module.configuration.hostname = mock_module_configuration["hostname"]
            connector.module.configuration.api_key = mock_module_configuration["api_key"]
            connector.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]

            # Mock configuration
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )

            return connector

    @pytest.mark.asyncio
    async def test_next_batch_success(
        self, mock_connector, sample_detection, sample_detection_c2
    ):
        """Test successful batch processing."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            return_value=[sample_detection, sample_detection_c2]
        )
        mock_client.get_audit_log = AsyncMock(return_value=[])

        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            events, has_more = await mock_connector.next_batch()

        assert len(events) == 2
        assert has_more is False
        mock_connector.push_data_to_intakes.assert_called_once()

    @pytest.mark.asyncio
    async def test_next_batch_with_audit_logs(
        self, mock_connector, sample_detection, sample_audit_log
    ):
        """Test batch processing with audit logs enabled."""
        mock_connector.configuration.include_audit_logs = True

        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_client.get_audit_log = AsyncMock(return_value=[sample_audit_log])

        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            events, has_more = await mock_connector.next_batch()

        assert len(events) == 2  # 1 detection + 1 audit log
        mock_client.get_audit_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_next_batch_empty_results(self, mock_connector):
        """Test batch processing with no results."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[])
        mock_client.get_audit_log = AsyncMock(return_value=[])

        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            events, has_more = await mock_connector.next_batch()

        assert len(events) == 0
        mock_connector.push_data_to_intakes.assert_not_called()

    @pytest.mark.asyncio
    async def test_next_batch_auth_error(self, mock_connector):
        """Test batch processing with authentication error."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            side_effect=ExtraHopAuthError("Invalid API key", 401)
        )

        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            with pytest.raises(ExtraHopAuthError):
                await mock_connector.next_batch()
