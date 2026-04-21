"""Tests for ExtraHop Detections Connector."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from extrahop.detections_connector import (
    ExtraHopDetectionsConnector,
    ExtraHopDetectionsConnectorConfiguration,
)
from extrahop.client.errors import ExtraHopAuthError, ExtraHopAPIError, ExtraHopRateLimitError


class TestExtraHopDetectionsConnectorConfiguration:
    """Tests for connector configuration."""

    def test_default_configuration(self):
        config = ExtraHopDetectionsConnectorConfiguration(intake_key="test-intake-key")
        assert config.intake_key == "test-intake-key"
        assert config is not None

    def test_custom_configuration(self):
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
        config_min = ExtraHopDetectionsConnectorConfiguration(intake_key="test", min_risk_score=0)
        assert config_min.min_risk_score == 0

        config_max = ExtraHopDetectionsConnectorConfiguration(intake_key="test", min_risk_score=99)
        assert config_max.min_risk_score == 99


class TestTimestampNormalization:
    """Tests for _normalize_timestamps helper."""

    def test_epoch_ms_to_iso(self):
        iso = ExtraHopDetectionsConnector._epoch_ms_to_iso(1704067200000)
        assert iso == "2024-01-01T00:00:00.000000Z"

    def test_epoch_ms_to_iso_none(self):
        assert ExtraHopDetectionsConnector._epoch_ms_to_iso(None) is None

    def test_epoch_ms_to_iso_invalid(self):
        assert ExtraHopDetectionsConnector._epoch_ms_to_iso("not_a_number") is None

    def test_normalize_timestamps_converts_all_fields(self, sample_detection):
        detection = dict(sample_detection)
        result = ExtraHopDetectionsConnector._normalize_timestamps(detection)
        # start_time, mod_time, update_time, create_time should be ISO 8601 strings
        assert isinstance(result["start_time"], str)
        assert "T" in result["start_time"]
        assert result["start_time"].endswith("Z")
        assert isinstance(result["mod_time"], str)

    def test_normalize_timestamps_ignores_none(self):
        event = {"start_time": None, "mod_time": 1704067200000}
        result = ExtraHopDetectionsConnector._normalize_timestamps(event)
        assert result["start_time"] is None
        assert isinstance(result["mod_time"], str)

    def test_normalize_timestamps_skips_missing_fields(self):
        event = {"id": 42}
        result = ExtraHopDetectionsConnector._normalize_timestamps(event)
        assert result == {"id": 42}


class TestDeduplication:
    """Tests for deduplication cache."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration, tmp_path):
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector.log = MagicMock()
            connector.log_exception = MagicMock()
            connector._data_path = str(tmp_path)
            connector.context_store = MagicMock()
            connector.context_store.__enter__ = MagicMock(return_value={})
            connector.context_store.__exit__ = MagicMock(return_value=False)
            from sekoia_automation.storage import PersistentJSON
            connector.event_cache_store = PersistentJSON("event_cache.json", str(tmp_path))
            connector.event_cache_ttl = timedelta(hours=48)
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    def test_compute_dedup_key_stable(self, mock_connector, sample_detection):
        key1 = mock_connector._compute_dedup_key(sample_detection)
        key2 = mock_connector._compute_dedup_key(sample_detection)
        assert key1 == key2
        assert len(key1) == 64  # SHA256 hex

    def test_compute_dedup_key_different_mod_time(self, mock_connector, sample_detection):
        key1 = mock_connector._compute_dedup_key(sample_detection)
        modified = dict(sample_detection, mod_time=sample_detection["mod_time"] + 1000)
        key2 = mock_connector._compute_dedup_key(modified)
        assert key1 != key2

    def test_is_new_event_first_time(self, mock_connector, sample_detection):
        key = mock_connector._compute_dedup_key(sample_detection)
        with patch("extrahop.detections_connector.METRICS"):
            assert mock_connector._is_new_event(key) is True

    def test_is_new_event_second_time(self, mock_connector, sample_detection):
        key = mock_connector._compute_dedup_key(sample_detection)
        with patch("extrahop.detections_connector.METRICS"):
            mock_connector._is_new_event(key)
            assert mock_connector._is_new_event(key) is False


class TestCheckpointManagement:
    """Tests for checkpoint management."""

    @pytest.fixture
    def mock_connector(self, mock_connector_configuration, tmp_path):
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector.log = MagicMock()
            connector._data_path = str(tmp_path)
            from sekoia_automation.storage import PersistentJSON
            connector.context_store = PersistentJSON("context.json", str(tmp_path))
            connector.event_cache_store = PersistentJSON("event_cache.json", str(tmp_path))
            connector.event_cache_ttl = timedelta(hours=48)
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    def test_last_checkpoint_default(self, mock_connector):
        """When no checkpoint saved, returns now - historical_days in epoch ms."""
        result = mock_connector.last_checkpoint()
        expected = datetime.now(timezone.utc) - timedelta(days=7)
        expected_ms = int(expected.timestamp() * 1000)
        # Allow ±10 seconds tolerance
        assert abs(result - expected_ms) < 10000

    def test_last_checkpoint_saved(self, mock_connector):
        """Returns saved checkpoint."""
        saved_ms = 1704067200000
        with mock_connector.context_store as c:
            c["last_detection_mod_time"] = saved_ms
        result = mock_connector.last_checkpoint()
        assert result == saved_ms

    def test_save_checkpoint(self, mock_connector):
        """Saves checkpoint to store."""
        mock_connector.save_checkpoint(1704067200000)
        with mock_connector.context_store as c:
            assert c["last_detection_mod_time"] == 1704067200000

    def test_last_checkpoint_invalid_value(self, mock_connector):
        """Invalid stored value falls back to default."""
        with mock_connector.context_store as c:
            c["last_detection_mod_time"] = "not_a_number"
        result = mock_connector.last_checkpoint()
        expected_ms = int(
            (datetime.now(timezone.utc) - timedelta(days=7)).timestamp() * 1000
        )
        assert abs(result - expected_ms) < 10000

    def test_last_audit_checkpoint_default(self, mock_connector):
        result = mock_connector.last_audit_checkpoint()
        expected_ms = int(
            (datetime.now(timezone.utc) - timedelta(days=7)).timestamp() * 1000
        )
        assert abs(result - expected_ms) < 10000

    def test_save_audit_checkpoint(self, mock_connector):
        mock_connector.save_audit_checkpoint(1704067200000)
        with mock_connector.context_store as c:
            assert c["last_audit_time"] == 1704067200000

    def test_reset_cursor_clears_checkpoint(self, mock_connector):
        """reset_cursor=True returns default and clears saved checkpoint."""
        mock_connector.configuration.reset_cursor = True
        # Pre-save a checkpoint
        with mock_connector.context_store as c:
            c["last_detection_mod_time"] = 1704067200000

        result = mock_connector.last_checkpoint()
        expected_ms = int(
            (datetime.now(timezone.utc) - timedelta(days=7)).timestamp() * 1000
        )
        assert abs(result - expected_ms) < 10000

        # Checkpoint should be cleared
        with mock_connector.context_store as c:
            assert c.get("last_detection_mod_time") is None


class TestFetchEvents:
    """Tests for fetch_events async generator."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration, tmp_path):
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector.log = MagicMock()
            connector.log_exception = MagicMock()
            connector._data_path = str(tmp_path)
            from sekoia_automation.storage import PersistentJSON
            connector.context_store = PersistentJSON("context.json", str(tmp_path))
            connector.event_cache_store = PersistentJSON("event_cache.json", str(tmp_path))
            connector.event_cache_ttl = timedelta(hours=48)
            connector._client = None
            connector.module = MagicMock()
            connector.module.configuration.hostname = mock_module_configuration["hostname"]
            connector.module.configuration.api_key = mock_module_configuration["api_key"]
            connector.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    @pytest.mark.asyncio
    async def test_fetch_events_yields_detections(
        self, mock_connector, sample_detection, sample_detection_c2
    ):
        """fetch_events yields detection batches."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            return_value=[sample_detection, sample_detection_c2]
        )
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.fetch_events():
                batches.append(batch)

        assert len(batches) >= 1
        all_events = [ev for b in batches for ev in b]
        assert len(all_events) == 2

    @pytest.mark.asyncio
    async def test_fetch_events_empty(self, mock_connector):
        """fetch_events yields nothing when no detections."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.fetch_events():
                batches.append(batch)

        assert batches == []

    @pytest.mark.asyncio
    async def test_fetch_events_deduplicates(self, mock_connector, sample_detection):
        """Same detection not yielded twice."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            # First call
            count1 = 0
            async for batch in mock_connector.fetch_events():
                count1 += len(batch)
            # Second call with same detection (already in cache)
            count2 = 0
            async for batch in mock_connector.fetch_events():
                count2 += len(batch)

        assert count1 == 1
        assert count2 == 0

    @pytest.mark.asyncio
    async def test_fetch_events_auth_error_propagates(self, mock_connector):
        """ExtraHopAuthError from fetch_all_detections propagates up."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            side_effect=ExtraHopAuthError("Invalid key", 401)
        )
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            with pytest.raises(ExtraHopAuthError):
                async for _ in mock_connector.fetch_events():
                    pass

    @pytest.mark.asyncio
    async def test_fetch_events_api_error_returns_empty(self, mock_connector):
        """ExtraHopAPIError from fetch_all_detections causes early return."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            side_effect=ExtraHopAPIError("Server error", 500)
        )
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.fetch_events():
                batches.append(batch)

        assert batches == []

    @pytest.mark.asyncio
    async def test_fetch_events_normalizes_timestamps(self, mock_connector, sample_detection):
        """Timestamps in yielded events are ISO 8601 strings."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            events = []
            async for batch in mock_connector.fetch_events():
                events.extend(batch)

        assert len(events) == 1
        assert isinstance(events[0]["start_time"], str)
        assert "T" in events[0]["start_time"]

    @pytest.mark.asyncio
    async def test_fetch_events_with_audit_logs(
        self, mock_connector, sample_detection, sample_audit_log
    ):
        """With include_audit_logs=True, audit log batch is also yielded."""
        mock_connector.configuration.include_audit_logs = True

        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_client.get_audit_log = AsyncMock(return_value=[sample_audit_log])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.fetch_events():
                batches.append(batch)

        # At least 2 batches: one for detections, one for audit logs
        all_events = [ev for b in batches for ev in b]
        assert len(all_events) == 2
        mock_client.get_audit_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_events_audit_logs_disabled(self, mock_connector, sample_detection):
        """With include_audit_logs=False, audit log API is not called."""
        mock_connector.configuration.include_audit_logs = False

        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_client.get_audit_log = AsyncMock(return_value=[])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            async for _ in mock_connector.fetch_events():
                pass

        mock_client.get_audit_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_events_updates_checkpoint(
        self, mock_connector, sample_detection, sample_detection_c2
    ):
        """Checkpoint is updated to max mod_time after fetching."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(
            return_value=[sample_detection, sample_detection_c2]
        )
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            async for _ in mock_connector.fetch_events():
                pass

        # max mod_time from sample_detection_c2 is 1704082000000
        with mock_connector.context_store as c:
            assert c.get("last_detection_mod_time") == 1704082000000


class TestNextBatch:
    """Tests for next_batch async generator."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration, tmp_path):
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector.log = MagicMock()
            connector._data_path = str(tmp_path)
            from sekoia_automation.storage import PersistentJSON
            connector.context_store = PersistentJSON("context.json", str(tmp_path))
            connector.event_cache_store = PersistentJSON("event_cache.json", str(tmp_path))
            connector.event_cache_ttl = timedelta(hours=48)
            connector._client = None
            connector.module = MagicMock()
            connector.module.configuration.hostname = mock_module_configuration["hostname"]
            connector.module.configuration.api_key = mock_module_configuration["api_key"]
            connector.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            connector.configuration = ExtraHopDetectionsConnectorConfiguration(
                **mock_connector_configuration
            )
            return connector

    @pytest.mark.asyncio
    async def test_next_batch_yields_batches(self, mock_connector, sample_detection):
        """next_batch yields event batches from fetch_events."""
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[sample_detection])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.next_batch():
                batches.append(batch)

        assert len(batches) >= 1

    @pytest.mark.asyncio
    async def test_next_batch_empty(self, mock_connector):
        mock_client = AsyncMock()
        mock_client.fetch_all_detections = AsyncMock(return_value=[])
        mock_connector._client = mock_client

        with patch("extrahop.detections_connector.METRICS"):
            batches = []
            async for batch in mock_connector.next_batch():
                batches.append(batch)

        assert batches == []


class TestClientManagement:
    """Tests for client lifecycle management."""

    @pytest.fixture
    def mock_connector(self, mock_module_configuration, mock_connector_configuration):
        with patch.object(ExtraHopDetectionsConnector, "__init__", lambda x: None):
            connector = ExtraHopDetectionsConnector()
            connector._client = None
            connector.module = MagicMock()
            connector.module.configuration.hostname = mock_module_configuration["hostname"]
            connector.module.configuration.api_key = mock_module_configuration["api_key"]
            connector.module.configuration.verify_ssl = mock_module_configuration["verify_ssl"]
            connector.module.configuration.client_id = ""
            connector.module.configuration.client_secret = ""
            return connector

    def test_client_property_creates_client(self, mock_connector):
        from extrahop.client.http_client import ExtraHopClient
        client = mock_connector.client
        assert isinstance(client, ExtraHopClient)
        assert client.hostname == "extrahop.example.com"

    def test_client_property_caches_client(self, mock_connector):
        client1 = mock_connector.client
        client2 = mock_connector.client
        assert client1 is client2

    @pytest.mark.asyncio
    async def test_close_client(self, mock_connector):
        mock_client = AsyncMock()
        mock_connector._client = mock_client

        await mock_connector._close_client()

        mock_client.close.assert_called_once()
        assert mock_connector._client is None

    @pytest.mark.asyncio
    async def test_close_client_when_none(self, mock_connector):
        mock_connector._client = None
        await mock_connector._close_client()  # Should not raise
        assert mock_connector._client is None
