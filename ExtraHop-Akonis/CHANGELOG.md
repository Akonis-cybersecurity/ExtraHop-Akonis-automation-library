# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-30

### Added

- Initial release of ExtraHop Reveal(x) NDR connector
- **Detections API**: Search and retrieve security detections with MITRE ATT&CK mappings
  - Support for filtering by categories, risk score, and status
  - Offset-based pagination with configurable batch size
  - Checkpoint-based incremental collection using `mod_time`
- **Audit Log API**: Retrieve system administration events
- **Devices API**: Search devices by criteria
- **Records API**: Search structured flow and transaction records
- **Alerts API**: Retrieve alert configurations
- **Authentication**: API key authentication (`Authorization: ExtraHop apikey=`)
- **Rate Limiting**: Client-side rate limiting (1 req/sec) with automatic backoff on 429
- **Error Handling**: Custom exceptions with automatic retries for transient errors
- **Deduplication**: TTL-based cache (7-day TTL, 50k entries) using `detection_id:mod_time`
- **Metrics**: Prometheus metrics for monitoring
  - Detections fetched/pushed counters
  - Detections by category/risk level/MITRE tactic
  - API request/error counters
  - Fetch duration histogram
  - Connector health gauge
- **Configuration Options**:
  - Detection categories filter
  - Minimum risk score threshold
  - Detection status filter
  - Polling frequency (1-60 minutes)
  - Historical days for first run (1-30 days)
  - Batch size (100-10000)
  - Optional audit log collection

### Security

- SSL certificate verification enabled by default
- API key stored as secret in configuration
- Non-root user in Docker container

[1.0.0]: https://github.com/SEKOIA-IO/automation-library
