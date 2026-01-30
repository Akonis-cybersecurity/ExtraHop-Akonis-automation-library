"""Tests for ExtraHop HTTP client."""

import pytest
from aioresponses import aioresponses

from extrahop.client.http_client import ExtraHopClient
from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopNotFoundError,
    ExtraHopRateLimitError,
)


@pytest.fixture
def client():
    """Create test client."""
    return ExtraHopClient(
        hostname="extrahop.example.com",
        api_key="test-api-key",
        verify_ssl=False,
    )


class TestExtraHopClientInit:
    """Tests for client initialization."""

    def test_init_basic(self):
        """Test basic client initialization."""
        client = ExtraHopClient(
            hostname="extrahop.example.com",
            api_key="test-key",
        )
        assert client.hostname == "extrahop.example.com"
        assert client.api_key == "test-key"
        assert client.verify_ssl is True
        assert client.base_url == "https://extrahop.example.com/api/v1"

    def test_init_with_trailing_slash(self):
        """Test hostname with trailing slash is normalized."""
        client = ExtraHopClient(
            hostname="extrahop.example.com/",
            api_key="test-key",
        )
        assert client.hostname == "extrahop.example.com"

    def test_headers_contain_auth(self):
        """Test headers include proper authentication."""
        client = ExtraHopClient(
            hostname="extrahop.example.com",
            api_key="my-api-key",
        )
        headers = client._headers
        assert headers["Authorization"] == "ExtraHop apikey=my-api-key"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"


class TestSearchDetections:
    """Tests for search_detections endpoint."""

    @pytest.mark.asyncio
    async def test_search_detections_basic(self, client, sample_detection):
        """Test basic detection search."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[sample_detection],
            )

            async with client:
                results = await client.search_detections()

            assert len(results) == 1
            assert results[0]["id"] == 12345

    @pytest.mark.asyncio
    async def test_search_detections_with_filters(self, client, sample_detection):
        """Test detection search with filters."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[sample_detection],
            )

            async with client:
                results = await client.search_detections(
                    mod_time=1704067200000,
                    categories=["sec", "sec.lateral"],
                    risk_score_min=50,
                    statuses=["new", "in_progress"],
                    limit=500,
                    offset=0,
                )

            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_search_detections_empty_result(self, client):
        """Test detection search with no results."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[],
            )

            async with client:
                results = await client.search_detections()

            assert results == []


class TestGetDetection:
    """Tests for get_detection endpoint."""

    @pytest.mark.asyncio
    async def test_get_detection_success(self, client, sample_detection):
        """Test getting a specific detection."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/12345",
                payload=sample_detection,
            )

            async with client:
                result = await client.get_detection(12345)

            assert result["id"] == 12345
            assert result["type"] == "lateral_movement_smb"

    @pytest.mark.asyncio
    async def test_get_detection_not_found(self, client):
        """Test getting non-existent detection."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/99999",
                status=404,
                payload={"error_message": "Detection not found"},
            )

            async with client:
                with pytest.raises(ExtraHopNotFoundError):
                    await client.get_detection(99999)


class TestGetDetectionFormats:
    """Tests for get_detection_formats endpoint."""

    @pytest.mark.asyncio
    async def test_get_detection_formats(self, client, sample_detection_formats):
        """Test getting detection formats."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/formats",
                payload=sample_detection_formats,
            )

            async with client:
                results = await client.get_detection_formats()

            assert len(results) == 3
            assert results[0]["type"] == "lateral_movement_smb"


class TestGetAuditLog:
    """Tests for get_audit_log endpoint."""

    @pytest.mark.asyncio
    async def test_get_audit_log(self, client, sample_audit_log):
        """Test getting audit logs."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/auditlog",
                payload=[sample_audit_log],
            )

            async with client:
                results = await client.get_audit_log()

            assert len(results) == 1
            assert results[0]["id"] == 1001

    @pytest.mark.asyncio
    async def test_get_audit_log_with_pagination(self, client, sample_audit_log):
        """Test getting audit logs with pagination."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/auditlog?limit=100&offset=50",
                payload=[sample_audit_log],
            )

            async with client:
                results = await client.get_audit_log(limit=100, offset=50)

            assert len(results) == 1


class TestSearchDevices:
    """Tests for search_devices endpoint."""

    @pytest.mark.asyncio
    async def test_search_devices(self, client, sample_device):
        """Test searching devices."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/devices/search",
                payload=[sample_device],
            )

            async with client:
                results = await client.search_devices()

            assert len(results) == 1
            assert results[0]["id"] == 5678

    @pytest.mark.asyncio
    async def test_search_devices_with_filter(self, client, sample_device):
        """Test searching devices with filter."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/devices/search",
                payload=[sample_device],
            )

            async with client:
                results = await client.search_devices(
                    filter_obj={"role": "workstation"},
                    limit=50,
                    offset=0,
                )

            assert len(results) == 1


class TestGetAlerts:
    """Tests for alerts endpoints."""

    @pytest.mark.asyncio
    async def test_get_alerts(self, client):
        """Test getting alerts."""
        sample_alerts = [
            {"id": 1, "name": "High CPU Alert"},
            {"id": 2, "name": "Bandwidth Alert"},
        ]
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/alerts",
                payload=sample_alerts,
            )

            async with client:
                results = await client.get_alerts()

            assert len(results) == 2


class TestSearchRecords:
    """Tests for search_records endpoint."""

    @pytest.mark.asyncio
    async def test_search_records(self, client):
        """Test searching records."""
        sample_records = [
            {"id": 1, "type": "http", "server": "example.com"},
        ]
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/records/search",
                payload=sample_records,
            )

            async with client:
                results = await client.search_records(
                    from_time=1704067200000,
                    until_time=1704153600000,
                    types=["~http"],
                )

            assert len(results) == 1


class TestErrorHandling:
    """Tests for error handling."""

    @pytest.mark.asyncio
    async def test_auth_error_401(self, client):
        """Test 401 authentication error."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/formats",
                status=401,
                payload={"error_message": "Invalid API key"},
            )

            async with client:
                with pytest.raises(ExtraHopAuthError) as exc_info:
                    await client.get_detection_formats()

            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_error_403(self, client):
        """Test 403 forbidden error."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/formats",
                status=403,
                payload={"error_message": "Insufficient privileges"},
            )

            async with client:
                with pytest.raises(ExtraHopAuthError) as exc_info:
                    await client.get_detection_formats()

            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_rate_limit_error(self, client):
        """Test 429 rate limit error."""
        with aioresponses() as mocked:
            # Mock multiple 429 responses to exhaust retries
            for _ in range(5):
                mocked.get(
                    "https://extrahop.example.com/api/v1/detections/formats",
                    status=429,
                    payload={"error_message": "Rate limit exceeded"},
                    headers={"Retry-After": "30"},
                )

            async with client:
                with pytest.raises(ExtraHopRateLimitError):
                    await client.get_detection_formats()

    @pytest.mark.asyncio
    async def test_api_error_500(self, client):
        """Test 500 server error."""
        with aioresponses() as mocked:
            # Mock multiple 500 responses to exhaust retries
            for _ in range(5):
                mocked.get(
                    "https://extrahop.example.com/api/v1/detections/formats",
                    status=500,
                    payload={"error_message": "Internal server error"},
                )

            async with client:
                with pytest.raises(ExtraHopAPIError) as exc_info:
                    await client.get_detection_formats()

            assert exc_info.value.status_code == 500


class TestTestConnection:
    """Tests for test_connection method."""

    @pytest.mark.asyncio
    async def test_connection_success(self, client, sample_detection_formats):
        """Test successful connection."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/formats",
                payload=sample_detection_formats,
            )

            async with client:
                result = await client.test_connection()

            assert result is True

    @pytest.mark.asyncio
    async def test_connection_auth_failure(self, client):
        """Test connection with auth failure."""
        with aioresponses() as mocked:
            mocked.get(
                "https://extrahop.example.com/api/v1/detections/formats",
                status=401,
                payload={"error_message": "Invalid API key"},
            )

            async with client:
                result = await client.test_connection()

            assert result is False


class TestFetchAllDetections:
    """Tests for fetch_all_detections method."""

    @pytest.mark.asyncio
    async def test_fetch_all_single_page(self, client, sample_detection):
        """Test fetching all detections with single page."""
        with aioresponses() as mocked:
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[sample_detection],
            )

            async with client:
                results = await client.fetch_all_detections(batch_size=1000)

            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_fetch_all_multiple_pages(self, client, sample_detection, sample_detection_c2):
        """Test fetching all detections with pagination."""
        with aioresponses() as mocked:
            # First page (full batch)
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[sample_detection] * 100,
            )
            # Second page (partial batch - end of results)
            mocked.post(
                "https://extrahop.example.com/api/v1/detections/search",
                payload=[sample_detection_c2] * 50,
            )

            async with client:
                results = await client.fetch_all_detections(batch_size=100)

            assert len(results) == 150
