"""
ExtraHop Detections Connector
Fetches security detections from ExtraHop Reveal(x) NDR platform.
"""

import asyncio
import hashlib
import signal
import time
from asyncio import sleep
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional

import orjson
from sekoia_automation.aio.connector import AsyncConnector
from sekoia_automation.connector import DefaultConnectorConfiguration
from sekoia_automation.storage import PersistentJSON

from extrahop import ExtraHopModule
from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopRateLimitError,
)
from extrahop.client.http_client import ExtraHopClient
from extrahop.metrics import METRICS


class ExtraHopDetectionsConnectorConfiguration(DefaultConnectorConfiguration):
    """Configuration for ExtraHop Detections Connector."""

    detection_categories: list = []
    min_risk_score: int = 0
    detection_statuses: list = []
    polling_frequency_minutes: int = 5
    historical_days: int = 7
    batch_size: int = 1000
    include_audit_logs: bool = False
    reset_cursor: bool = False


class ExtraHopDetectionsConnector(AsyncConnector):
    """
    Connector to retrieve security detections from ExtraHop Reveal(x) NDR.

    Follows the same pattern as AnozrwayHistoricalConnector:
    - sync run() with own event loop
    - next_batch() as AsyncGenerator yielding raw event batches
    - push_data_to_intakes in _async_run loop
    - raw events pushed to intake, parser.yml handles ECS mapping
    """

    name = "ExtraHopDetectionsConnector"
    module: ExtraHopModule
    configuration: ExtraHopDetectionsConnectorConfiguration

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client: ExtraHopClient | None = None

        self.context_store = PersistentJSON("context.json", self._data_path)
        self.event_cache_store = PersistentJSON("event_cache.json", self._data_path)
        self.event_cache_ttl = timedelta(hours=48)

        self.log(
            message=(
                f"ExtraHopDetectionsConnector initialized - "
                f"Data path: {self._data_path}, "
                f"Frequency: {self.configuration.polling_frequency_minutes}m, "
                f"Batch size: {self.configuration.batch_size}"
            ),
            level="info",
        )

    @property
    def client(self) -> ExtraHopClient:
        """Get or create HTTP client."""
        if self._client is None:
            cfg = self.module.configuration
            self._client = ExtraHopClient(
                hostname=cfg.hostname,
                api_key=cfg.api_key,
                client_id=cfg.client_id,
                client_secret=cfg.client_secret,
                verify_ssl=cfg.verify_ssl,
            )
        return self._client

    async def _close_client(self) -> None:
        """Close HTTP client."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # Checkpoint management (PersistentJSON, like Anozrway)
    # ------------------------------------------------------------------
    def last_checkpoint(self) -> int:
        """Return last mod_time checkpoint; default = now - historical_days (epoch ms).

        If reset_cursor is True, ignores the saved checkpoint, recalculates from
        historical_days, clears the dedup cache, and marks the reset as done.
        """
        default_start = datetime.now(timezone.utc) - timedelta(
            days=int(self.configuration.historical_days)
        )
        default_ms = int(default_start.timestamp() * 1000)

        # Check if reset was requested — always reset on every poll while True
        if self.configuration.reset_cursor:
            self.log(
                message=(
                    f"reset_cursor=True: historical_days={self.configuration.historical_days}, "
                    f"now={datetime.now(timezone.utc).isoformat()}, "
                    f"start={default_start.isoformat()}, mod_time={default_ms}"
                ),
                level="info",
            )
            with self.context_store as c:
                c["last_detection_mod_time"] = None
                c["last_audit_time"] = None

            # Clear dedup cache so historical events are not skipped
            with self.event_cache_store as s:
                for k in list(s.keys()):
                    del s[k]

            return default_ms

        with self.context_store as c:
            val = c.get("last_detection_mod_time")
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    self.log(
                        message=f"Invalid checkpoint '{val}', falling back to default",
                        level="warning",
                    )
                    return default_ms
        return default_ms

    def save_checkpoint(self, mod_time: int) -> None:
        """Persist the mod_time checkpoint."""
        run_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self.context_store as c:
            c["last_detection_mod_time"] = mod_time
            c["last_successful_run"] = run_time

    def last_audit_checkpoint(self) -> int:
        """Return last audit checkpoint (epoch ms)."""
        default_start = datetime.now(timezone.utc) - timedelta(
            days=int(self.configuration.historical_days)
        )
        default_ms = int(default_start.timestamp() * 1000)

        with self.context_store as c:
            val = c.get("last_audit_time")
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return default_ms
        return default_ms

    def save_audit_checkpoint(self, ts: int) -> None:
        """Persist the audit checkpoint."""
        with self.context_store as c:
            c["last_audit_time"] = ts

    # ------------------------------------------------------------------
    # Deduplication (PersistentJSON cache, like Anozrway)
    # ------------------------------------------------------------------
    def _cleanup_event_cache(self) -> None:
        cutoff = datetime.now(timezone.utc) - self.event_cache_ttl
        cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")

        with self.event_cache_store as s:
            keys = list(s.keys())
            for k in keys:
                try:
                    if str(s[k]) < cutoff_iso:
                        del s[k]
                except Exception:
                    del s[k]

    def _compute_dedup_key(self, detection: Dict[str, Any]) -> str:
        """Build a stable dedup key from detection id + mod_time."""
        detection_id = str(detection.get("id", ""))
        mod_time = str(detection.get("mod_time", ""))
        raw = f"{detection_id}|{mod_time}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _is_new_event(self, cache_key: str) -> bool:
        with self.event_cache_store as s:
            if cache_key in s:
                METRICS.deduplication_hits.inc()
                return False
            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            s[cache_key] = now_iso
            return True

    # ------------------------------------------------------------------
    # Timestamp normalization (epoch ms → ISO 8601)
    # ------------------------------------------------------------------
    @staticmethod
    def _epoch_ms_to_iso(epoch_ms: Any) -> Optional[str]:
        """Convert epoch milliseconds to ISO 8601 UTC string."""
        if epoch_ms is None:
            return None
        try:
            ts = int(epoch_ms) / 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, TypeError, OSError):
            return None

    @classmethod
    def _normalize_timestamps(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert all epoch ms fields to ISO 8601 in-place for parser compatibility."""
        for field in ("start_time", "end_time", "update_time", "mod_time", "create_time", "occur_time"):
            if field in event and event[field] is not None:
                iso = cls._epoch_ms_to_iso(event[field])
                if iso:
                    event[field] = iso
        return event

    # ------------------------------------------------------------------
    # Fetch & collect (yields raw event batches, like Anozrway)
    # ------------------------------------------------------------------
    async def fetch_events(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Collect detections (and optionally audit logs) from ExtraHop API.

        Yields batches of raw event dicts ready to be serialized and pushed.
        """
        self._cleanup_event_cache()

        intake_key = self.configuration.intake_key
        chunk_size = self.configuration.batch_size

        # --- Detections ---
        mod_time = self.last_checkpoint()
        self.log(
            message=f"Fetching detections modified since {mod_time}",
            level="info",
        )

        categories = self.configuration.detection_categories or None
        statuses = self.configuration.detection_statuses or None
        risk_score_min = self.configuration.min_risk_score or None

        try:
            t0 = time.time()
            detections = await self.client.fetch_all_detections(
                mod_time=mod_time,
                categories=categories,
                risk_score_min=risk_score_min,
                statuses=statuses,
                batch_size=chunk_size,
            )
            METRICS.fetch_duration.observe(time.time() - t0)
            METRICS.detections_fetched.inc(len(detections))

            self.log(
                message=f"Fetched {len(detections)} detections from API",
                level="info",
            )
        except ExtraHopAuthError:
            raise
        except ExtraHopAPIError as e:
            self.log(message=f"API error fetching detections: {e}", level="error")
            METRICS.api_errors.labels(error_type="api", endpoint="detections").inc()
            return

        if not detections:
            self.log(message="No new detections found", level="info")
        else:
            max_mod_time: int = 0
            batch: List[Dict[str, Any]] = []

            for detection in detections:
                key = self._compute_dedup_key(detection)
                if not self._is_new_event(key):
                    continue

                # Track max mod_time for checkpoint (before normalization)
                det_mod_time = detection.get("mod_time", 0)
                if isinstance(det_mod_time, int) and det_mod_time > max_mod_time:
                    max_mod_time = det_mod_time

                # Normalize epoch ms timestamps to ISO 8601
                detection = self._normalize_timestamps(dict(detection))

                # Update metrics
                for category in detection.get("categories", []):
                    METRICS.detections_by_category.labels(category=category).inc()
                for tactic in detection.get("mitre_tactics", []):
                    METRICS.detections_by_mitre_tactic.labels(tactic=tactic).inc()

                risk_score = detection.get("risk_score", 0)
                if risk_score >= 75:
                    risk_level = "critical"
                elif risk_score >= 50:
                    risk_level = "high"
                elif risk_score >= 30:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                METRICS.detections_by_risk.labels(risk_level=risk_level).inc()

                batch.append(detection)

                if len(batch) >= chunk_size:
                    yield batch
                    batch = []

            if batch:
                yield batch

            if max_mod_time > 0:
                self.save_checkpoint(max_mod_time)

        # --- Audit logs (optional) ---
        if self.configuration.include_audit_logs:
            try:
                audit_logs = await self.client.get_audit_log(limit=1000)
                self.log(
                    message=f"Fetched {len(audit_logs)} audit log entries",
                    level="info",
                )
                if audit_logs:
                    yield [self._normalize_timestamps(dict(ev)) for ev in audit_logs]
            except ExtraHopAPIError as e:
                self.log(message=f"Failed to fetch audit logs: {e}", level="warning")

    async def next_batch(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Yield event batches from fetch_events."""
        async for batch in self.fetch_events():
            yield batch

    # ------------------------------------------------------------------
    # Main run loop (sync, like Anozrway)
    # ------------------------------------------------------------------
    def run(self) -> None:  # pragma: no cover
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def handle_stop_signal() -> None:
            loop.create_task(self.shutdown())

        loop.add_signal_handler(signal.SIGTERM, handle_stop_signal)
        loop.add_signal_handler(signal.SIGINT, handle_stop_signal)

        try:
            loop.run_until_complete(self._async_run())
        except ExtraHopAuthError as e:
            self.log_exception(e, message="CRITICAL: Authentication failed - Check API key")
        except Exception as e:
            self.log_exception(e, message="Unexpected error in connector execution")
        finally:
            loop.run_until_complete(self._close_client())
            loop.close()

    async def _async_run(self) -> None:
        """Async main loop: fetch batches, serialize raw events, push to intake."""
        self.log(message="Starting ExtraHop Detections Connector", level="info")

        # Log auth mode
        auth_mode = "OAuth2" if self.module.configuration.use_oauth2 else "API key"
        self.log(
            message=f"Auth mode: {auth_mode}, Hostname: {self.module.configuration.hostname}",
            level="info",
        )

        # Test connection
        try:
            await self.client.test_connection()
            self.log(message="Successfully connected to ExtraHop API", level="info")
        except ExtraHopAuthError as e:
            self.log(
                message=f"Authentication failed ({auth_mode}): {e} - Check credentials in module configuration",
                level="error",
            )
            return
        except Exception as e:
            self.log(
                message=(
                    f"Failed to connect to ExtraHop API: {e} - "
                    f"Hostname: {self.module.configuration.hostname}, "
                    f"Base URL: {self.client.base_url}, "
                    f"SSL verify: {self.module.configuration.verify_ssl}"
                ),
                level="error",
            )
            return

        intake_key = self.configuration.intake_key
        frequency = self.configuration.polling_frequency_minutes * 60

        while self.running:
            try:
                batch_count = 0
                async for batch in self.next_batch():
                    batch_count += 1
                    self.log(
                        message=f"Pushing batch {batch_count} to intake - Events: {len(batch)}",
                        level="info",
                    )
                    serialized = [orjson.dumps(ev).decode("utf-8") for ev in batch]
                    await self.push_data_to_intakes(events=serialized)
                    METRICS.detections_pushed.inc(len(batch))

                METRICS.connector_health.set(1)
                METRICS.last_successful_fetch.set(time.time())

                await sleep(frequency)

            except ExtraHopAuthError:
                raise
            except ExtraHopRateLimitError as e:
                wait_time = e.retry_after or 60
                self.log(
                    message=f"Rate limited, waiting {wait_time}s",
                    level="warning",
                )
                await sleep(wait_time)
            except Exception as e:
                METRICS.connector_health.set(0)
                self.log_exception(e, message="Error in collection loop - retry in 60s")
                await sleep(60)
