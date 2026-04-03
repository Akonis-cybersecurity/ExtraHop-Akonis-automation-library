"""
Async HTTP client for ExtraHop REST API.
Implements all API endpoints with proper authentication, rate limiting, and error handling.
Supports both API key (on-prem) and OAuth2 client credentials (RevealX 360 cloud).
"""

import time
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

    Authentication modes:
    - API key: Authorization: ExtraHop apikey=... (on-prem appliances)
    - OAuth2 client credentials: Bearer token from /oauth2/token (RevealX 360 cloud)
    """

    def __init__(
        self,
        hostname: str,
        api_key: str = "",
        client_id: str = "",
        client_secret: str = "",
        verify_ssl: bool = True,
        rate_limit: float = 1.0,
        timeout: int = 30,
    ):
        self.hostname = hostname.rstrip("/")
        self.api_key = api_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.base_url = f"https://{self.hostname}/api/v1"

        # OAuth2 state
        self._use_oauth2 = bool(client_id and client_secret)
        self._oauth2_token: str | None = None
        self._oauth2_token_expires_at: float = 0.0
        self._token_url = f"https://{self.hostname}/oauth2/token"

        # Rate limiter: default 1 request/second
        self._rate_limiter = AsyncLimiter(max_rate=rate_limit, time_period=1)
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # OAuth2 token management
    # ------------------------------------------------------------------
    async def _ensure_oauth2_token(self) -> str:
        """Get a valid OAuth2 Bearer token, refreshing if expired."""
        # Return cached token if still valid (with 60s safety margin)
        if self._oauth2_token and time.time() < (self._oauth2_token_expires_at - 60):
            return self._oauth2_token

        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
        ) as session:
            async with session.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            ) as resp:
                if resp.status != 200:
                    try:
                        body = await resp.text()
                    except Exception:
                        body = f"HTTP {resp.status}"
                    raise ExtraHopAuthError(
                        message=f"OAuth2 token request failed: {body}",
                        status_code=resp.status,
                    )
                data = await resp.json()

        self._oauth2_token = data["access_token"]
        expires_in = int(data.get("expires_in", 3600))
        self._oauth2_token_expires_at = time.time() + expires_in
        return self._oauth2_token

    def _invalidate_oauth2_token(self) -> None:
        """Force token refresh on next request."""
        self._oauth2_token = None
        self._oauth2_token_expires_at = 0.0

    # ------------------------------------------------------------------
    # Session / headers
    # ------------------------------------------------------------------
    async def _get_auth_headers(self) -> dict[str, str]:
        """Build authentication headers depending on auth mode."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._use_oauth2:
            token = await self._ensure_oauth2_token()
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["Authorization"] = f"ExtraHop apikey={self.api_key}"
        return headers

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session.

        For OAuth2, we recreate the session when the token changes
        because headers are set at session level.
        """
        needs_new = self._session is None or self._session.closed

        if self._use_oauth2:
            # Ensure token is valid; if it was refreshed the session headers are stale
            token = await self._ensure_oauth2_token()
            current_auth = f"Bearer {token}"
            if self._session and not self._session.closed:
                existing_auth = self._session.headers.get("Authorization", "")
                if existing_auth != current_auth:
                    await self._session.close()
                    needs_new = True

        if needs_new:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            headers = await self._get_auth_headers()
            self._session = aiohttp.ClientSession(
                headers=headers,
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
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return urljoin(self.base_url + "/", path.lstrip("/"))

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------
    async def _handle_response(self, response: aiohttp.ClientResponse) -> dict[str, Any] | list[Any]:
        if response.status == 200:
            return await response.json()

        if response.status in (201, 204):
            try:
                return await response.json()
            except Exception:
                return {}

        try:
            error_data = await response.json()
            error_message = error_data.get("error_message", str(error_data))
        except Exception:
            error_message = await response.text() or f"HTTP {response.status}"

        if response.status == 401:
            # Invalidate cached OAuth2 token on 401 so next retry gets a fresh one
            if self._use_oauth2:
                self._invalidate_oauth2_token()
                if self._session and not self._session.closed:
                    await self._session.close()
                    self._session = None
            raise ExtraHopAuthError(
                message=f"Authentication failed (401): {error_message}",
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
        result = await self._request("GET", f"/detections/{detection_id}")
        return result if isinstance(result, dict) else {}

    async def get_detection_formats(self) -> list[dict[str, Any]]:
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
        body: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }
        if filter_obj:
            body["filter"] = filter_obj

        result = await self._request("POST", "/devices/search", json_data=body)
        return result if isinstance(result, list) else []

    async def get_device(self, device_id: int) -> dict[str, Any]:
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
        result = await self._request("GET", "/alerts")
        return result if isinstance(result, list) else []

    async def get_alert(self, alert_id: int) -> dict[str, Any]:
        result = await self._request("GET", f"/alerts/{alert_id}")
        return result if isinstance(result, dict) else {}

    # =========================================================================
    # METRICS API
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
        """Test API connectivity and authentication.

        Raises on failure so the connector can log the exact error.
        """
        await self.get_detection_formats()
        return True

    async def fetch_all_detections(
        self,
        mod_time: int | None = None,
        categories: list[str] | None = None,
        risk_score_min: int | None = None,
        statuses: list[str] | None = None,
        batch_size: int = 1000,
    ) -> list[dict[str, Any]]:
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

            if len(batch) < batch_size:
                break

        return all_detections
