"""
Async HTTP client for ExtraHop REST API.
Implements all API endpoints with proper authentication, rate limiting, and error handling.
"""

import asyncio
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aiolimiter import AsyncLimiter
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopNotFoundError,
    ExtraHopRateLimitError,
)


class ExtraHopClient:
    """
    Async HTTP client for ExtraHop REST API.

    Implements:
    - API key authentication (Authorization: ExtraHop apikey=...)
    - Rate limiting (1 request/second)
    - Automatic retries with exponential backoff
    - All major API endpoints
    """

    def __init__(
        self,
        hostname: str,
        api_key: str,
        verify_ssl: bool = True,
        rate_limit: float = 1.0,
        timeout: int = 30,
    ):
        """
        Initialize ExtraHop API client.

        Args:
            hostname: ExtraHop appliance hostname or IP
            api_key: REST API key
            verify_ssl: Verify SSL certificates
            rate_limit: Max requests per second
            timeout: Request timeout in seconds
        """
        self.hostname = hostname.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.base_url = f"https://{self.hostname}/api/v1"

        # Rate limiter: default 1 request/second
        self._rate_limiter = AsyncLimiter(max_rate=rate_limit, time_period=1)
        self._session: aiohttp.ClientSession | None = None

    @property
    def _headers(self) -> dict[str, str]:
        """Build request headers with authentication."""
        return {
            "Authorization": f"ExtraHop apikey={self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self._session = aiohttp.ClientSession(
                headers=self._headers,
                timeout=self.timeout,
                connector=connector,
            )
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "ExtraHopClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return urljoin(self.base_url + "/", path.lstrip("/"))

    async def _handle_response(self, response: aiohttp.ClientResponse) -> dict[str, Any] | list[Any]:
        """
        Handle API response and raise appropriate exceptions.

        Args:
            response: aiohttp response object

        Returns:
            Parsed JSON response

        Raises:
            ExtraHopAuthError: On 401/403
            ExtraHopNotFoundError: On 404
            ExtraHopRateLimitError: On 429
            ExtraHopAPIError: On other errors
        """
        if response.status == 200:
            return await response.json()

        # Try to get error message from response
        try:
            error_data = await response.json()
            error_message = error_data.get("error_message", str(error_data))
        except Exception:
            error_message = await response.text() or f"HTTP {response.status}"

        if response.status == 401:
            raise ExtraHopAuthError(
                message="Invalid or revoked API key",
                status_code=401,
                response={"error": error_message},
            )

        if response.status == 403:
            raise ExtraHopAuthError(
                message=f"Insufficient privileges: {error_message}",
                status_code=403,
                response={"error": error_message},
            )

        if response.status == 404:
            raise ExtraHopNotFoundError(
                message=error_message,
                status_code=404,
            )

        if response.status == 429:
            retry_after = response.headers.get("Retry-After")
            raise ExtraHopRateLimitError(
                message="Rate limit exceeded",
                retry_after=int(retry_after) if retry_after else None,
            )

        raise ExtraHopAPIError(
            message=error_message,
            status_code=response.status,
        )

    @retry(
        retry=retry_if_exception_type((ExtraHopRateLimitError, aiohttp.ClientError)),
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(initial=2, max=120, jitter=5),
        reraise=True,
    )
    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """
        Make an API request with rate limiting and retries.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            params: Query parameters
            json_data: JSON body data

        Returns:
            Parsed JSON response
        """
        async with self._rate_limiter:
            session = await self._get_session()
            url = self._build_url(path)

            async with session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
            ) as response:
                return await self._handle_response(response)

    # =========================================================================
    # DETECTIONS API
    # =========================================================================

    async def search_detections(
        self,
        mod_time: int | None = None,
        from_time: int | None = None,
        until_time: int | None = None,
        categories: list[str] | None = None,
        risk_score_min: int | None = None,
        statuses: list[str] | None = None,
        types: list[str] | None = None,
        limit: int = 1000,
        offset: int = 0,
        sort_field: str = "mod_time",
        sort_direction: str = "asc",
    ) -> list[dict[str, Any]]:
        """
        Search for security detections.

        Args:
            mod_time: Return detections modified after this timestamp (ms since epoch)
            from_time: Beginning timestamp (ms since epoch)
            until_time: Ending timestamp (ms since epoch)
            categories: Filter by categories (e.g., ["sec", "sec.lateral"])
            risk_score_min: Minimum risk score (0-99)
            statuses: Filter by status (new, in_progress, closed, acknowledged)
            types: Filter by detection type identifiers
            limit: Maximum results (max 10000)
            offset: Number of results to skip
            sort_field: Sort field (mod_time, creation_time)
            sort_direction: Sort direction (asc, desc)

        Returns:
            List of detection objects
        """
        body: dict[str, Any] = {
            "limit": min(limit, 10000),
            "offset": offset,
            "sort": [{"field": sort_field, "direction": sort_direction}],
        }

        if mod_time is not None:
            body["mod_time"] = mod_time

        if from_time is not None:
            body["from"] = from_time

        if until_time is not None:
            body["until"] = until_time

        # Build filter object
        filter_obj: dict[str, Any] = {}

        if categories:
            filter_obj["categories"] = categories

        if risk_score_min is not None:
            filter_obj["risk_score_min"] = risk_score_min

        if statuses:
            filter_obj["status"] = statuses

        if types:
            filter_obj["types"] = types

        if filter_obj:
            body["filter"] = filter_obj

        result = await self._request("POST", "/detections/search", json_data=body)
        return result if isinstance(result, list) else []

    async def get_detection(self, detection_id: int) -> dict[str, Any]:
        """
        Get detailed information about a specific detection.

        Args:
            detection_id: Unique identifier for the detection

        Returns:
            Detection object
        """
        result = await self._request("GET", f"/detections/{detection_id}")
        return result if isinstance(result, dict) else {}

    async def get_detection_formats(self) -> list[dict[str, Any]]:
        """
        Get all available detection types.

        Returns:
            List of detection format objects
        """
        result = await self._request("GET", "/detections/formats")
        return result if isinstance(result, list) else []

    async def update_detection(
        self,
        detection_id: int,
        status: str | None = None,
        assignee: str | None = None,
        resolution: str | None = None,
        ticket_id: str | None = None,
        ticket_url: str | None = None,
    ) -> dict[str, Any]:
        """
        Update a detection's status, assignee, or ticket information.

        Args:
            detection_id: Detection ID to update
            status: New status (new, in_progress, closed, acknowledged)
            assignee: Username to assign
            resolution: Resolution (action_taken, no_action_taken)
            ticket_id: External ticket ID
            ticket_url: External ticket URL

        Returns:
            Updated detection object
        """
        body: dict[str, Any] = {}

        if status is not None:
            body["status"] = status
        if assignee is not None:
            body["assignee"] = assignee
        if resolution is not None:
            body["resolution"] = resolution
        if ticket_id is not None:
            body["ticket_id"] = ticket_id
        if ticket_url is not None:
            body["ticket_url"] = ticket_url

        result = await self._request("PATCH", f"/detections/{detection_id}", json_data=body)
        return result if isinstance(result, dict) else {}

    # =========================================================================
    # AUDIT LOG API
    # =========================================================================

    async def get_audit_log(
        self,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve system administration and configuration audit events.

        Args:
            limit: Maximum number of entries to return
            offset: Number of entries to skip

        Returns:
            List of audit log entries
        """
        params: dict[str, Any] = {}

        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset

        result = await self._request("GET", "/auditlog", params=params if params else None)
        return result if isinstance(result, list) else []

    # =========================================================================
    # DEVICES API
    # =========================================================================

    async def search_devices(
        self,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Search for devices matching specific criteria.

        Args:
            filter_obj: Device filter criteria
            limit: Maximum number of devices to return
            offset: Number of devices to skip

        Returns:
            List of device objects
        """
        body: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }

        if filter_obj:
            body["filter"] = filter_obj

        result = await self._request("POST", "/devices/search", json_data=body)
        return result if isinstance(result, list) else []

    async def get_device(self, device_id: int) -> dict[str, Any]:
        """
        Get detailed information about a specific device.

        Args:
            device_id: Unique identifier for the device

        Returns:
            Device object
        """
        result = await self._request("GET", f"/devices/{device_id}")
        return result if isinstance(result, dict) else {}

    # =========================================================================
    # RECORDS API
    # =========================================================================

    async def search_records(
        self,
        from_time: int,
        until_time: int,
        types: list[str] | None = None,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Search for structured flow and transaction records.

        Args:
            from_time: Beginning timestamp (ms since epoch)
            until_time: Ending timestamp (ms since epoch)
            types: Record types to search (e.g., ["~http", "~dns"])
            filter_obj: Record filter criteria
            limit: Maximum records to return
            offset: Number of records to skip

        Returns:
            List of record objects
        """
        body: dict[str, Any] = {
            "from": from_time,
            "until": until_time,
            "limit": limit,
            "offset": offset,
        }

        if types:
            body["types"] = types

        if filter_obj:
            body["filter"] = filter_obj

        result = await self._request("POST", "/records/search", json_data=body)
        return result if isinstance(result, list) else []

    # =========================================================================
    # ALERTS API
    # =========================================================================

    async def get_alerts(self) -> list[dict[str, Any]]:
        """
        Get all configured alerts.

        Returns:
            List of alert configuration objects
        """
        result = await self._request("GET", "/alerts")
        return result if isinstance(result, list) else []

    async def get_alert(self, alert_id: int) -> dict[str, Any]:
        """
        Get a specific alert configuration.

        Args:
            alert_id: Alert ID

        Returns:
            Alert configuration object
        """
        result = await self._request("GET", f"/alerts/{alert_id}")
        return result if isinstance(result, dict) else {}

    # =========================================================================
    # METRICS API (Bonus - useful for enrichment)
    # =========================================================================

    async def get_metrics(
        self,
        cycle: str,
        from_time: int,
        until_time: int,
        metric_category: str,
        metric_specs: list[dict[str, Any]],
        object_type: str,
        object_ids: list[int],
    ) -> dict[str, Any]:
        """
        Query metrics for devices or applications.

        Args:
            cycle: Time granularity (30sec, 5min, 1hr, 24hr)
            from_time: Start timestamp (ms since epoch)
            until_time: End timestamp (ms since epoch)
            metric_category: Category of metrics
            metric_specs: List of metric specifications
            object_type: Type of object (device, application)
            object_ids: List of object IDs

        Returns:
            Metrics data
        """
        body: dict[str, Any] = {
            "cycle": cycle,
            "from": from_time,
            "until": until_time,
            "metric_category": metric_category,
            "metric_specs": metric_specs,
            "object_type": object_type,
            "object_ids": object_ids,
        }

        result = await self._request("POST", "/metrics", json_data=body)
        return result if isinstance(result, dict) else {}

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    async def test_connection(self) -> bool:
        """
        Test API connectivity and authentication.

        Returns:
            True if connection successful
        """
        try:
            await self.get_detection_formats()
            return True
        except ExtraHopAuthError:
            return False
        except Exception:
            return False

    async def fetch_all_detections(
        self,
        mod_time: int | None = None,
        categories: list[str] | None = None,
        risk_score_min: int | None = None,
        statuses: list[str] | None = None,
        batch_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Fetch all detections with automatic pagination.

        Args:
            mod_time: Return detections modified after this timestamp
            categories: Filter by categories
            risk_score_min: Minimum risk score
            statuses: Filter by status
            batch_size: Number of detections per request

        Yields:
            Detection objects
        """
        all_detections: list[dict[str, Any]] = []
        offset = 0

        while True:
            batch = await self.search_detections(
                mod_time=mod_time,
                categories=categories,
                risk_score_min=risk_score_min,
                statuses=statuses,
                limit=batch_size,
                offset=offset,
            )

            if not batch:
                break

            all_detections.extend(batch)
            offset += len(batch)

            # If we got less than batch_size, we've reached the end
            if len(batch) < batch_size:
                break

        return all_detections
