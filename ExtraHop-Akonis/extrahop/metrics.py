"""
Prometheus metrics for ExtraHop connector.
"""

from prometheus_client import Counter, Gauge, Histogram


class ExtraHopMetrics:
    """Container for all ExtraHop connector metrics."""

    def __init__(self, prefix: str = "extrahop"):
        # Detection counters
        self.detections_fetched = Counter(
            f"{prefix}_detections_fetched_total",
            "Total detections fetched from ExtraHop",
        )

        self.detections_pushed = Counter(
            f"{prefix}_detections_pushed_total",
            "Total detections pushed to SEKOIA.IO intake",
        )

        self.detections_by_category = Counter(
            f"{prefix}_detections_by_category_total",
            "Detections grouped by category",
            ["category"],
        )

        self.detections_by_risk = Counter(
            f"{prefix}_detections_by_risk_level_total",
            "Detections grouped by risk level",
            ["risk_level"],
        )

        self.detections_by_mitre_tactic = Counter(
            f"{prefix}_detections_by_mitre_tactic_total",
            "Detections grouped by MITRE ATT&CK tactic",
            ["tactic"],
        )

        # API metrics
        self.api_requests = Counter(
            f"{prefix}_api_requests_total",
            "Total API requests to ExtraHop",
            ["endpoint", "status_code"],
        )

        self.api_errors = Counter(
            f"{prefix}_api_errors_total",
            "Total API errors encountered",
            ["error_type", "endpoint"],
        )

        # Deduplication
        self.deduplication_hits = Counter(
            f"{prefix}_deduplication_hits_total",
            "Number of duplicate detections filtered",
        )

        # Performance
        self.fetch_duration = Histogram(
            f"{prefix}_fetch_duration_seconds",
            "Time taken to fetch detections from ExtraHop",
            buckets=[0.5, 1, 2, 5, 10, 30, 60, 120],
        )

        # Health
        self.connector_health = Gauge(
            f"{prefix}_connector_health",
            "Connector health status (1=healthy, 0=unhealthy)",
        )

        self.last_successful_fetch = Gauge(
            f"{prefix}_last_successful_fetch_timestamp",
            "Unix timestamp of last successful detection fetch",
        )


# Global metrics instance
METRICS = ExtraHopMetrics()
