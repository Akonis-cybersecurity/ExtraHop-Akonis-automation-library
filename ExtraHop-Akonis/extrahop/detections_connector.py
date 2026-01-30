"""
ExtraHop Detections Connector
Fetches security detections from ExtraHop Reveal(x) NDR platform.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from cachetools import TTLCache
from pydantic import BaseModel, Field
from sekoia_automation.aio.connector import AsyncConnector
from sekoia_automation.connector import DefaultConnectorConfiguration

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

    # Filtering options
    detection_categories: list[str] = Field(
        default=[],
        description="Detection categories to collect (empty for all). "
        "Examples: sec, sec.attack, sec.lateral, sec.ransomware, perf",
    )

    min_risk_score: int = Field(
        default=0,
        ge=0,
        le=99,
        description="Minimum risk score for detections (0-99)",
    )

    detection_statuses: list[str] = Field(
        default=["new", "in_progress", "acknowledged"],
        description="Detection statuses to collect",
    )

    # Polling options
    polling_frequency_minutes: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Minutes between each poll (1-60)",
    )

    historical_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description="Days of historical data to fetch on first run",
    )

    # Advanced options
    batch_size: int = Field(
        default=1000,
        ge=100,
        le=10000,
        description="Number of detections to fetch per API request",
    )

    include_audit_logs: bool = Field(
        default=False,
        description="Also collect audit log events",
    )


class ExtraHopDetectionsConnector(AsyncConnector):
    """
    Connector to retrieve security detections from ExtraHop Reveal(x) NDR.

    Features:
    - Polls detections API with configurable filters
    - Supports MITRE ATT&CK tactic/technique mapping
    - Deduplication using detection ID + mod_time
    - Checkpoint-based incremental collection
    - Optional audit log collection
    """

    name = "ExtraHopDetectionsConnector"
    module: ExtraHopModule
    configuration: ExtraHopDetectionsConnectorConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client: ExtraHopClient | None = None

        # Deduplication cache: 7-day TTL, 50k max entries
        self._seen_detections: TTLCache = TTLCache(
            maxsize=50000,
            ttl=604800,  # 7 days
        )

        # Checkpoint keys
        self._checkpoint_key_detections = "last_detection_mod_time"
        self._checkpoint_key_audit = "last_audit_time"

    @property
    def client(self) -> ExtraHopClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = ExtraHopClient(
                hostname=self.module.configuration.hostname,
                api_key=self.module.configuration.api_key,
                verify_ssl=self.module.configuration.verify_ssl,
            )
        return self._client

    async def _close_client(self) -> None:
        """Close HTTP client."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    def _get_checkpoint(self, key: str) -> int | None:
        """Get checkpoint value from context."""
        try:
            value = self.context.get(key)
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    def _set_checkpoint(self, key: str, value: int) -> None:
        """Set checkpoint value in context."""
        self.context[key] = value

    def _get_initial_mod_time(self) -> int:
        """Get initial mod_time for first run (historical_days back)."""
        days_back = self.configuration.historical_days
        start_time = datetime.now(timezone.utc) - timedelta(days=days_back)
        return int(start_time.timestamp() * 1000)

    def _is_duplicate(self, detection: dict[str, Any]) -> bool:
        """
        Check if detection was already processed.

        Uses detection_id:mod_time as cache key to handle updates.
        """
        detection_id = detection.get("id")
        mod_time = detection.get("mod_time")

        if detection_id is None or mod_time is None:
            return False

        cache_key = f"{detection_id}:{mod_time}"

        if cache_key in self._seen_detections:
            return True

        self._seen_detections[cache_key] = True
        return False

    def _format_detection_event(self, detection: dict[str, Any]) -> str:
        """
        Format detection for SEKOIA.IO intake.

        Adds metadata and converts to JSON string.
        """
        # Add event metadata
        event = {
            "event": {
                "kind": "alert",
                "type": ["info"],
                "category": ["intrusion_detection", "network"],
                "module": "extrahop",
                "dataset": "extrahop.detections",
            },
            "observer": {
                "vendor": "ExtraHop",
                "product": "Reveal(x)",
                "type": "ids",
            },
            "extrahop": {
                "detection": detection,
            },
        }

        # Map risk score to severity
        risk_score = detection.get("risk_score", 0)
        if risk_score >= 75:
            event["event"]["severity"] = 4
            event["event"]["severity_label"] = "critical"
        elif risk_score >= 50:
            event["event"]["severity"] = 3
            event["event"]["severity_label"] = "high"
        elif risk_score >= 30:
            event["event"]["severity"] = 2
            event["event"]["severity_label"] = "medium"
        else:
            event["event"]["severity"] = 1
            event["event"]["severity_label"] = "low"

        # Extract MITRE mappings
        mitre_tactics = detection.get("mitre_tactics", [])
        mitre_techniques = detection.get("mitre_techniques", [])

        if mitre_tactics or mitre_techniques:
            event["threat"] = {}
            if mitre_tactics:
                event["threat"]["tactic"] = {"id": mitre_tactics}
            if mitre_techniques:
                event["threat"]["technique"] = {"id": mitre_techniques}

        # Extract participant info (source/destination)
        participants = detection.get("participants", [])
        for participant in participants:
            role = participant.get("role", "").lower()
            if role == "offender":
                event["source"] = {
                    "ip": participant.get("ipaddr"),
                    "hostname": participant.get("hostname"),
                    "mac": participant.get("macaddr"),
                }
            elif role == "victim":
                event["destination"] = {
                    "ip": participant.get("ipaddr"),
                    "hostname": participant.get("hostname"),
                    "mac": participant.get("macaddr"),
                }

        return json.dumps(event)

    def _format_audit_event(self, audit_entry: dict[str, Any]) -> str:
        """Format audit log entry for SEKOIA.IO intake."""
        event = {
            "event": {
                "kind": "event",
                "type": ["info"],
                "category": ["configuration"],
                "module": "extrahop",
                "dataset": "extrahop.auditlog",
            },
            "observer": {
                "vendor": "ExtraHop",
                "product": "Reveal(x)",
                "type": "ids",
            },
            "extrahop": {
                "audit": audit_entry,
            },
        }

        # Extract user info
        body = audit_entry.get("body", {})
        if "user" in body:
            event["user"] = {"name": body["user"]}

        return json.dumps(event)

    async def _fetch_detections(self) -> list[dict[str, Any]]:
        """Fetch detections from ExtraHop API."""
        # Get checkpoint or use initial time
        mod_time = self._get_checkpoint(self._checkpoint_key_detections)
        if mod_time is None:
            mod_time = self._get_initial_mod_time()
            self.log(
                message=f"No checkpoint found, starting from {self.configuration.historical_days} days ago",
                level="info",
            )

        self.log(
            message=f"Fetching detections modified since {mod_time}",
            level="info",
        )

        # Build category filter
        categories = self.configuration.detection_categories or None
        statuses = self.configuration.detection_statuses or None
        risk_score_min = self.configuration.min_risk_score or None

        try:
            detections = await self.client.fetch_all_detections(
                mod_time=mod_time,
                categories=categories,
                risk_score_min=risk_score_min,
                statuses=statuses,
                batch_size=self.configuration.batch_size,
            )

            self.log(
                message=f"Fetched {len(detections)} detections from API",
                level="info",
            )

            # Update metrics
            METRICS.detections_fetched.inc(len(detections))

            return detections

        except ExtraHopAuthError as e:
            self.log(message=f"Authentication error: {e}", level="error")
            METRICS.api_errors.labels(error_type="auth", endpoint="detections").inc()
            raise

        except ExtraHopRateLimitError as e:
            self.log(message=f"Rate limit error: {e}", level="warning")
            METRICS.api_errors.labels(error_type="rate_limit", endpoint="detections").inc()
            raise

        except ExtraHopAPIError as e:
            self.log(message=f"API error: {e}", level="error")
            METRICS.api_errors.labels(error_type="api", endpoint="detections").inc()
            raise

    async def _fetch_audit_logs(self) -> list[dict[str, Any]]:
        """Fetch audit logs from ExtraHop API."""
        if not self.configuration.include_audit_logs:
            return []

        try:
            audit_logs = await self.client.get_audit_log(limit=1000)
            self.log(
                message=f"Fetched {len(audit_logs)} audit log entries",
                level="info",
            )
            return audit_logs

        except ExtraHopAPIError as e:
            self.log(message=f"Failed to fetch audit logs: {e}", level="warning")
            return []

    async def _process_detections(self, detections: list[dict[str, Any]]) -> list[str]:
        """Process detections and return formatted events."""
        events: list[str] = []
        max_mod_time: int = 0

        for detection in detections:
            # Skip duplicates
            if self._is_duplicate(detection):
                METRICS.deduplication_hits.inc()
                continue

            # Track max mod_time for checkpoint
            mod_time = detection.get("mod_time", 0)
            if mod_time > max_mod_time:
                max_mod_time = mod_time

            # Format and collect event
            event = self._format_detection_event(detection)
            events.append(event)

            # Update category metrics
            categories = detection.get("categories", [])
            risk_score = detection.get("risk_score", 0)

            for category in categories:
                METRICS.detections_by_category.labels(category=category).inc()

            # Map risk to level
            if risk_score >= 75:
                risk_level = "critical"
            elif risk_score >= 50:
                risk_level = "high"
            elif risk_score >= 30:
                risk_level = "medium"
            else:
                risk_level = "low"
            METRICS.detections_by_risk.labels(risk_level=risk_level).inc()

            # Update MITRE metrics
            for tactic in detection.get("mitre_tactics", []):
                METRICS.detections_by_mitre_tactic.labels(tactic=tactic).inc()

        # Update checkpoint
        if max_mod_time > 0:
            self._set_checkpoint(self._checkpoint_key_detections, max_mod_time)
            self.log(
                message=f"Updated checkpoint to {max_mod_time}",
                level="debug",
            )

        return events

    async def _process_audit_logs(self, audit_logs: list[dict[str, Any]]) -> list[str]:
        """Process audit logs and return formatted events."""
        events: list[str] = []

        for entry in audit_logs:
            event = self._format_audit_event(entry)
            events.append(event)

        return events

    async def next_batch(self) -> tuple[list[str], bool]:
        """
        Fetch and process next batch of events.

        Returns:
            Tuple of (events list, has_more flag)
        """
        all_events: list[str] = []

        try:
            # Fetch detections
            start_time = time.time()
            detections = await self._fetch_detections()
            fetch_duration = time.time() - start_time
            METRICS.fetch_duration.observe(fetch_duration)

            # Process detections
            detection_events = await self._process_detections(detections)
            all_events.extend(detection_events)

            # Fetch and process audit logs if enabled
            if self.configuration.include_audit_logs:
                audit_logs = await self._fetch_audit_logs()
                audit_events = await self._process_audit_logs(audit_logs)
                all_events.extend(audit_events)

            # Update health metrics
            METRICS.connector_health.set(1)
            METRICS.last_successful_fetch.set(time.time())

            self.log(
                message=f"Processed {len(all_events)} events ({len(detection_events)} detections)",
                level="info",
            )

            # Push events
            if all_events:
                METRICS.detections_pushed.inc(len(all_events))
                await self.push_data_to_intakes(all_events)

            return all_events, False

        except Exception as e:
            METRICS.connector_health.set(0)
            self.log(message=f"Error in next_batch: {e}", level="error")
            raise

    async def run(self) -> None:
        """Main connector loop."""
        self.log(message="Starting ExtraHop Detections Connector", level="info")

        # Test connection
        try:
            if not await self.client.test_connection():
                self.log(message="Failed to connect to ExtraHop API", level="error")
                return
            self.log(message="Successfully connected to ExtraHop API", level="info")
        except Exception as e:
            self.log(message=f"Connection test failed: {e}", level="error")
            return

        poll_interval = self.configuration.polling_frequency_minutes * 60

        try:
            while self.running:
                try:
                    await self.next_batch()

                except ExtraHopAuthError:
                    self.log(
                        message="Authentication failed - check API key",
                        level="critical",
                    )
                    break

                except ExtraHopRateLimitError as e:
                    wait_time = e.retry_after or 60
                    self.log(
                        message=f"Rate limited, waiting {wait_time}s",
                        level="warning",
                    )
                    await asyncio.sleep(wait_time)
                    continue

                except Exception as e:
                    self.log(message=f"Error in polling loop: {e}", level="error")
                    await asyncio.sleep(60)
                    continue

                # Wait for next poll
                self.log(
                    message=f"Sleeping for {poll_interval}s until next poll",
                    level="debug",
                )
                await asyncio.sleep(poll_interval)

        finally:
            await self._close_client()
            self.log(message="ExtraHop Detections Connector stopped", level="info")
