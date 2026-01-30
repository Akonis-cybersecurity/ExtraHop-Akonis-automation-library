# ExtraHop Reveal(x) NDR - Integration Specification

## Table of Contents

- [Architecture](#architecture)
- [Specification](#specification)
- [Github](#github)
- [Repositories](#repositories)
- [Context](#context)
- [Connector](#connector)
- [Format](#format)
- [Documentation](#documentation)
- [Deliverable](#deliverable)
- [Implementation Notes](#implementation-notes)
- [Blockers & Dependencies](#blockers--dependencies)

---

# Architecture

## Commercial URL of the product

- https://www.extrahop.com/products/revealx/

## Type of technology

- On-premises (Appliance)
- Cloud (RevealX 360)
- Hybrid

### Reason for choosing technology type

- ExtraHop Reveal(x) is a Network Detection and Response (NDR) platform that provides real-time visibility into network traffic, detects security threats using machine learning and behavioral analysis, and maps findings to MITRE ATT&CK framework. It can be deployed as physical/virtual appliances on-premises or as a cloud service (RevealX 360).

## Product version (on-prem)

- ExtraHop 26.1+ (REST API v1)
- RevealX 360 (Cloud)

### Prerequisites to use integration (module, plan, role, permission, etc.)

- **ExtraHop System**: Active ExtraHop Reveal(x) deployment (sensor, console, or RevealX 360)
- **API Key**: REST API key with appropriate privileges
- **Privilege Level**: User with "metrics": "full" or higher privilege level for detection access
- **NDR Module**: "ndr": "full" privilege for security detections
- **Network Access**: HTTPS connectivity from Sekoia.io to ExtraHop appliance (port 443)
- **TLS Certificate**: Valid TLS certificate or self-signed certificate configured

**Important Notes:**
- API keys can only be viewed by the user who generated them or by system administrators
- Each user generates their own API key from Administration settings
- Cross-origin resource sharing (CORS) may need configuration for external access
- Rate limits apply: typically 30-60 requests per minute depending on endpoint

## Detection use-case

Sekoia considers the following scenarios of detection:

- **Threat oriented**: Raise new alerts in Sekoia using available detection engine to detect threats based on built-in rules and CTI correlation with ExtraHop detection data (e.g., correlating network indicators with threat intelligence)
- **Pass-through**: Forward ExtraHop detections directly to Sekoia as alerts, preserving MITRE ATT&CK mappings and risk scores

**Both scenarios apply** for ExtraHop integration. ExtraHop's ML-based detections are high-value security events that should be forwarded as-is, while the rich network metadata enables additional correlation in Sekoia.

## Available event types

ExtraHop provides several API endpoints with different event types:

1. **Detections API** (`/detections/search`)
   - Security and performance detections with ML-based analysis
   - MITRE ATT&CK tactics and techniques mapping
   - Risk scoring (0-99)
   - Participant information (devices, IPs, users)
   - Detection categories: Security (sec.*) and Performance (perf.*)

2. **Audit Log API** (`/auditlog`)
   - System administration activities
   - Configuration changes
   - User access events

3. **Records API** (`/records/search`)
   - Structured flow and transaction records
   - Network protocol details (HTTP, DNS, CIFS, etc.)
   - Deep packet inspection data

4. **Alerts API** (`/alerts`)
   - Threshold-based alerts
   - Custom alert configurations

## Chosen event types

| Event type | Description |
| --- | --- |
| Security Detections | ML-based security detections with MITRE ATT&CK mappings including: attack, botnet, C2, cryptomining, DoS, exfiltration, exploitation, lateral movement, ransomware, reconnaissance |
| Performance Detections | Network performance anomalies: authentication issues, database problems, service degradation, storage issues |
| Audit Logs | System administration events and configuration changes |

## Chosen event fields

### Detection Response Fields

| Field name | Description | Type | Mandatory |
|-----------|------------|------|-----------|
| id | Unique identifier for the detection | integer | Yes |
| type | Detection type identifier | string | Yes |
| title | Display name of the detection | string | Yes |
| description | Detailed description of the detection | string | No |
| categories | Detection categories (sec.*, perf.*) | array[string] | Yes |
| risk_score | Risk score from 0-99 | integer | Yes |
| status | Detection status (new, in_progress, closed, acknowledged) | string | No |
| resolution | Detection resolution (action_taken, no_action_taken) | string | No |
| assignee | User assigned to the detection | string | No |
| start_time | When the detection started (ms since epoch) | integer | Yes |
| end_time | When the detection ended (ms since epoch) | integer | No |
| create_time | When the detection was created (ms since epoch) | integer | Yes |
| mod_time | Last modification time (ms since epoch) | integer | Yes |
| update_time | Last update time for related events (ms since epoch) | integer | Yes |
| mitre_tactics | MITRE ATT&CK tactics | array[string] | No |
| mitre_techniques | MITRE ATT&CK techniques | array[string] | No |
| participants | Devices and applications involved | array[object] | Yes |
| properties | Detection-specific properties | object | No |
| appliance_id | ID of the appliance that generated the detection | integer | Yes |
| ticket_id | Associated ticket ID | string | No |
| ticket_url | URL to associated ticket | string | No |
| url | URL to detection in ExtraHop UI | string | Yes |

### Participant Object Fields

| Field name | Description | Type |
|-----------|------------|------|
| id | Participant unique identifier | integer |
| object_type | Type of participant (device, application) | string |
| object_id | ID of the device or application | integer |
| role | Role in the detection (offender, victim) | string |
| hostname | Device hostname | string |
| ipaddr | IP address | string |
| macaddr | MAC address | string |
| usernames | Associated usernames | array[string] |
| origins | Origin IP addresses | array[string] |

### Audit Log Response Fields

| Field name | Description | Type | Mandatory |
|-----------|------------|------|-----------|
| id | Unique identifier for the audit entry | integer | Yes |
| time | Timestamp of the event (ms since epoch) | integer | Yes |
| occur_time | When the event occurred (ms since epoch) | integer | Yes |
| body | Event details object | object | Yes |
| body.action | Action performed | string | Yes |
| body.user | User who performed the action | string | No |
| body.detail | Additional details | string | No |

## Log collection method

### Available methods

- [X] PULL (REST API) - **Primary method**
- [ ] PUSH (Webhook) - Not available
- [ ] Syslog - Available but not recommended for structured data

### Chosen method

- **PULL (REST API)** for Detections API and Audit Log API

### Reason for choosing this method

1. **Rich structured data**: REST API provides full detection context including MITRE mappings
2. **Pagination support**: Handles large volumes of detections efficiently
3. **Filtering capabilities**: Can filter by categories, risk score, status, time range
4. **Checkpoint support**: mod_time parameter enables incremental collection
5. **Standard authentication**: Simple API key authentication
6. **No infrastructure changes**: No need to configure webhook endpoints or syslog forwarding

### Prerequisites for log collection

1. **API Key**: Generate REST API key from ExtraHop Administration settings
2. **Network Access**: HTTPS connectivity on port 443
3. **User Privileges**: User with "ndr": "full" for security detections
4. **TLS Configuration**: Valid or trusted self-signed certificate

### Log collection schema

```
+-------------+                    +--------------+                    +-------------+
|   Sekoia    |  HTTPS + API Key   |   ExtraHop   |  Detection Search  |  ExtraHop   |
|  Connector  |<------------------>|   REST API   |<------------------>|   ML/NDR    |
|             |  Authorization:    |   /api/v1    |  POST /detections/ |   Engine    |
|             |  ExtraHop apikey=  |              |       search       |             |
+-------------+                    +--------------+                    +-------------+
      |
      | 1. Request detections with mod_time filter
      | 2. Iterate through paginated results (limit/offset)
      | 3. Parse detection with MITRE mappings
      | 4. Enrich with participant details
      | 5. Deduplicate using detection ID + mod_time
      | 6. Forward events to Sekoia intake
      | 7. Update checkpoint with last mod_time
      +---> Repeat every 5 minutes
```

---

# Specification

## Github

*Github link*: https://github.com/SEKOIA-IO/automation-library

## Repositories

Location of the module: https://github.com/SEKOIA-IO/automation-library

---

# Context

### Product version

- **REST API**: v1 (stable)
- **Documentation**: https://docs.extrahop.com/current/rest-api-guide/
- **API Explorer**: https://{hostname}/api/v1/explore/

### Vendor description

ExtraHop is a leader in Network Detection and Response (NDR), providing real-time visibility and threat detection for enterprise networks. The Reveal(x) platform uses machine learning and behavioral analysis to detect security threats, maps findings to MITRE ATT&CK framework, and provides deep network forensics capabilities. ExtraHop monitors east-west and north-south traffic to detect lateral movement, data exfiltration, and other sophisticated attacks.

### Integration

*This integration enables collection of security detections from ExtraHop Reveal(x) NDR platform, providing comprehensive network-based threat visibility with MITRE ATT&CK context.*

*This development consists of:*

- *The creation of a connector to fetch security detections from ExtraHop REST API*
- *The creation of a format to parse ExtraHop detection events with MITRE mappings*
- *The documentation about this integration*

---

# Connector

## Description

The connector will implement a **polling-based approach** to fetch security detections from ExtraHop:

1. **Detections Connector**: Polls every 5 minutes for new and modified detections using mod_time checkpoint
2. **Filtering**: Supports filtering by categories (security/performance), risk score, and status
3. **MITRE Enrichment**: Preserves MITRE ATT&CK tactics and techniques from ExtraHop

**Architecture Decision**: Single connector focused on detections with configurable category and risk score filters.

## Access

### Type of authentication

- [X] API Key (ExtraHop apikey header)

### Authentication credentials required

The connector will need the following configuration:

**Module-level:**
- **ExtraHop Hostname**: Hostname or IP of ExtraHop appliance (e.g., `extrahop.company.com`)
- **API Key**: REST API key generated from Administration settings

**Connector-level:**
- **Detection Categories**: Filter by category (sec.*, perf.*, or all)
- **Minimum Risk Score**: Threshold for detection risk score (0-99)
- **Detection Statuses**: Filter by status (new, in_progress, acknowledged, closed)

## Credentials

Example configuration:

```yaml
# Module configuration
extrahop_hostname: extrahop.company.com
api_key: 2bc07e55971d4c9a88d0bb4d29ecbb29

# Connector configuration
detection_categories:
  - sec
  - sec.attack
  - sec.lateral
  - sec.ransomware
  - sec.exfil
min_risk_score: 30
detection_statuses:
  - new
  - in_progress
frequency: 300  # 5 minutes
```

## Authentication

### API Key Authentication

The connector must append the API key to request headers for all API calls.

**Request Header:**

```bash
GET https://extrahop.company.com/api/v1/detections/search
Content-Type: application/json
Accept: application/json
Authorization: ExtraHop apikey=2bc07e55971d4c9a88d0bb4d29ecbb29
```

**API Key Generation:**

1. Log in to ExtraHop Administration settings
2. Navigate to Access Settings > API Access
3. In "Generate an API Key" section, enter description
4. Click Generate and copy the key

### Handling authentication error

**Error Response Example:**

```json
{
  "error_message": "API key is invalid or has been revoked"
}
```

**HTTP Status Codes:**
- `401 Unauthorized`: Invalid or revoked API key
- `403 Forbidden`: Insufficient privileges for requested operation
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded

**Error handling strategy:**
1. On 401: Log critical error and stop connector (requires API key regeneration)
2. On 403: Log critical error and verify user privileges
3. On 429: Implement exponential backoff with jitter
4. On 5xx: Retry with exponential backoff (max 5 attempts)

## Get events

### Detections Search Endpoint

**Endpoint:**

```bash
POST https://{hostname}/api/v1/detections/search
Content-Type: application/json
Authorization: ExtraHop apikey={api_key}
```

**Request Body:**

```json
{
  "mod_time": 1704067200000,
  "filter": {
    "categories": ["sec", "sec.attack", "sec.lateral"],
    "risk_score_min": 30,
    "status": ["new", "in_progress"]
  },
  "limit": 1000,
  "offset": 0,
  "sort": [
    {
      "field": "mod_time",
      "direction": "asc"
    }
  ]
}
```

**Required Parameters:**
- None (all parameters are optional)

**Optional Parameters:**
- `from`: Beginning timestamp (ms since epoch)
- `until`: Ending timestamp (ms since epoch)
- `mod_time`: Return detections modified after this time (ms since epoch)
- `create_time`: Return detections created after this time
- `filter`: Filter criteria object
- `limit`: Maximum results (default: 1000, max: 10000)
- `offset`: Skip N results for pagination
- `sort`: Sort order (field: mod_time/creation_time, direction: asc/desc)

**Example Request:**

```bash
POST https://extrahop.company.com/api/v1/detections/search
Content-Type: application/json
Authorization: ExtraHop apikey=2bc07e55971d4c9a88d0bb4d29ecbb29

{
  "mod_time": 1704067200000,
  "filter": {
    "categories": ["sec"],
    "risk_score_min": 50
  },
  "limit": 1000,
  "offset": 0,
  "sort": [{"field": "mod_time", "direction": "asc"}]
}
```

### Response Format

#### Detection Response

```json
{
  "appliance_id": 1,
  "assignee": "security_analyst",
  "categories": ["sec", "sec.lateral"],
  "create_time": 1704067200000,
  "description": "A device on the network is communicating with an unusual number of internal hosts, which could indicate lateral movement or reconnaissance.",
  "end_time": 1704070800000,
  "id": 12345,
  "is_user_created": false,
  "mitre_tactics": ["TA0008"],
  "mitre_techniques": ["T1021", "T1021.002"],
  "mod_time": 1704071000000,
  "participants": [
    {
      "id": 1,
      "object_type": "device",
      "object_id": 5678,
      "role": "offender",
      "hostname": "WORKSTATION-01",
      "ipaddr": "192.168.1.100",
      "macaddr": "00:1A:2B:3C:4D:5E"
    },
    {
      "id": 2,
      "object_type": "device",
      "object_id": 5679,
      "role": "victim",
      "hostname": "SERVER-DC01",
      "ipaddr": "192.168.1.10",
      "macaddr": "00:1A:2B:3C:4D:5F"
    }
  ],
  "properties": {
    "unique_hosts_count": 45,
    "protocols": ["SMB", "RDP"]
  },
  "recommended": true,
  "recommended_factors": ["high_risk_score", "active_investigation"],
  "resolution": null,
  "risk_score": 75,
  "start_time": 1704067200000,
  "status": "in_progress",
  "ticket_id": "INC0012345",
  "ticket_url": "https://servicenow.company.com/incident/INC0012345",
  "title": "Lateral Movement - SMB/Admin Activity",
  "type": "lateral_movement_smb",
  "update_time": 1704071000000,
  "url": "https://extrahop.company.com/extrahop/#/detections/12345"
}
```

### Parameters definition

**Filter Parameters:**
- `categories`: Array of category strings (sec.*, perf.*)
- `status`: Array of statuses (new, in_progress, closed, acknowledged)
- `risk_score_min`: Minimum risk score (0-99)
- `assignee`: Filter by assignee (use ".none" for unassigned, ".me" for current user)
- `types`: Array of detection type identifiers
- `resolution`: Filter by resolution (action_taken, no_action_taken)
- `recommended`: Boolean to filter recommended detections

**Time Parameters:**
- `mod_time`: Detections modified after this timestamp (best for incremental polling)
- `from`/`until`: Time range for detection occurrence
- `create_time`: Detections created after this timestamp

### Parameters to use

The connector will use:

**Detection Polling:**
- `mod_time`: From checkpoint (last successful mod_time)
- `filter.categories`: From connector configuration
- `filter.risk_score_min`: From connector configuration
- `filter.status`: From connector configuration
- `limit`: 1000 (process in batches)
- `offset`: For pagination through results
- `sort`: `[{"field": "mod_time", "direction": "asc"}]`

### Pagination

**Pagination Type:**
- [X] Offset-based pagination

**Pagination Strategy:**

1. **Limit/Offset**: Use limit (max 10000) and offset parameters
2. **Sort by mod_time ascending**: Ensures consistent ordering
3. **Checkpoint updates**: Store max mod_time after each batch

**Example Collection Pattern:**

```python
# First request
POST /detections/search
{
  "mod_time": checkpoint_time,
  "limit": 1000,
  "offset": 0,
  "sort": [{"field": "mod_time", "direction": "asc"}]
}

# If 1000 results returned, fetch next page
POST /detections/search
{
  "mod_time": checkpoint_time,
  "limit": 1000,
  "offset": 1000,
  "sort": [{"field": "mod_time", "direction": "asc"}]
}

# Continue until fewer than limit results returned
```

**Indicator of end:** Results count < limit

## Rate-limit

### Rate limits

- **Requests per minute**: 30-60 depending on endpoint
- **No hard-coded global limit**: Varies by deployment

**Important**: Rate limits are configurable per deployment. Monitor 429 responses.

### Response headers

**Rate limit headers:**
- [ ] Not documented in API (monitor 429 responses)

### Rate limiting handling

**Rate Limit Error Response:**

```json
{
  "error_message": "Rate limit exceeded"
}
```

**HTTP Status Code**: `429 Too Many Requests`

**Connector Strategy:**
1. Implement client-side rate limiting: 1 request/second
2. On 429 error:
   - Use exponential backoff starting at 30 seconds
   - Log warning with retry timing
   - Max 5 retry attempts
3. Use `aiolimiter.AsyncLimiter(max_rate=1, time_period=1)` for proactive rate control

## Timestepper

**Recommended Configuration:**

### Detections Polling:
- **Polling interval**: 300 seconds (5 minutes)
- **Checkpoint field**: `mod_time`
- **Collection pattern**: Incremental using mod_time filter

**Example:**
```python
# Run at 10:00
mod_time filter: 2026-01-15T09:55:00+00:00 (last checkpoint)
# Returns detections modified since last run

# Run at 10:05
mod_time filter: 2026-01-15T10:00:00+00:00 (updated checkpoint)
```

## Checkpoint

**Checkpoint Strategy:**

Use `mod_time` field (last modification timestamp) as checkpoint reference.

### Checkpoint Data to Persist

```json
{
  "last_mod_time": 1704071000000,
  "last_detection_id": 12345,
  "last_successful_run": "2026-01-15T10:00:00+00:00",
  "total_detections_fetched": 1500
}
```

### Checkpoint Logic

1. On startup, read `last_mod_time` from checkpoint
2. If no checkpoint, use current time - 7 days (one week backfill)
3. Query API with `mod_time = last_mod_time`
4. After successful batch processing:
   - Find maximum `mod_time` in batch
   - Update checkpoint with this value
5. On next run, continue from last checkpoint

## Cache

**Deduplication Strategy:**

Use detection ID + mod_time as cache key to prevent duplicate forwarding during overlapping queries.

### Cache Key Format

```python
cache_key = f"{detection_id}:{mod_time}"
```

### Example Cache Entry

```python
"12345:1704071000000"
```

### Cache Implementation

**Cache Configuration:**
```python
from cachetools import TTLCache

# Detection cache: 7-day TTL
detection_cache = TTLCache(maxsize=50000, ttl=604800)
```

**Deduplication Logic:**
```python
def is_new_detection(detection: dict, cache: TTLCache) -> bool:
    """Check if detection is new using cache"""
    cache_key = f"{detection['id']}:{detection['mod_time']}"

    if cache_key in cache:
        return False  # Duplicate

    cache[cache_key] = True
    return True  # New detection
```

---

# Format

## Definition

The integration will require **one primary format**:

1. **ExtraHop Detections** - Parse security and performance detections with MITRE ATT&CK mappings

The format will parse events into ECS (Elastic Common Schema) compatible format for ingestion into Sekoia.

## Samples (anonymized)

### Sample Detection 1 - Lateral Movement

```json
{
  "appliance_id": 1,
  "categories": ["sec", "sec.lateral"],
  "create_time": 1704067200000,
  "description": "A device is using administrative credentials to access multiple internal systems via SMB.",
  "end_time": null,
  "id": 12345,
  "is_user_created": false,
  "mitre_tactics": ["TA0008"],
  "mitre_techniques": ["T1021", "T1021.002"],
  "mod_time": 1704071000000,
  "participants": [
    {
      "id": 1,
      "object_type": "device",
      "object_id": 5678,
      "role": "offender",
      "hostname": "WORKSTATION-FINANCE-01",
      "ipaddr": "192.168.10.100",
      "macaddr": "00:1A:2B:3C:4D:5E"
    },
    {
      "id": 2,
      "object_type": "device",
      "object_id": 5679,
      "role": "victim",
      "hostname": "DC-PROD-01",
      "ipaddr": "192.168.1.10",
      "macaddr": "00:1A:2B:3C:4D:5F"
    }
  ],
  "properties": {
    "unique_hosts": 23,
    "admin_shares_accessed": ["C$", "ADMIN$"]
  },
  "risk_score": 85,
  "start_time": 1704067200000,
  "status": "new",
  "title": "Lateral Movement - SMB/Admin Activity",
  "type": "lateral_movement_smb",
  "update_time": 1704071000000,
  "url": "https://extrahop.example.com/extrahop/#/detections/12345"
}
```

### Sample Detection 2 - Command and Control

```json
{
  "appliance_id": 1,
  "categories": ["sec", "sec.command"],
  "create_time": 1704080000000,
  "description": "Device communicating with known malicious domain using encrypted DNS over HTTPS.",
  "end_time": null,
  "id": 12346,
  "is_user_created": false,
  "mitre_tactics": ["TA0011"],
  "mitre_techniques": ["T1071", "T1071.001", "T1573"],
  "mod_time": 1704082000000,
  "participants": [
    {
      "id": 1,
      "object_type": "device",
      "object_id": 6789,
      "role": "offender",
      "hostname": "LAPTOP-DEV-03",
      "ipaddr": "192.168.20.50",
      "macaddr": "00:2B:3C:4D:5E:6F"
    }
  ],
  "properties": {
    "domain": "malicious-c2.example.com",
    "protocol": "DNS over HTTPS",
    "request_count": 150
  },
  "risk_score": 92,
  "start_time": 1704080000000,
  "status": "new",
  "title": "Command and Control - Suspicious DNS Activity",
  "type": "c2_dns_tunnel",
  "update_time": 1704082000000,
  "url": "https://extrahop.example.com/extrahop/#/detections/12346"
}
```

### Sample Detection 3 - Data Exfiltration

```json
{
  "appliance_id": 1,
  "categories": ["sec", "sec.exfil"],
  "create_time": 1704090000000,
  "description": "Unusual volume of data being transferred to external cloud storage service.",
  "end_time": 1704093600000,
  "id": 12347,
  "is_user_created": false,
  "mitre_tactics": ["TA0010"],
  "mitre_techniques": ["T1567", "T1567.002"],
  "mod_time": 1704094000000,
  "participants": [
    {
      "id": 1,
      "object_type": "device",
      "object_id": 7890,
      "role": "offender",
      "hostname": "FILESERVER-01",
      "ipaddr": "192.168.5.20",
      "macaddr": "00:3C:4D:5E:6F:70"
    }
  ],
  "properties": {
    "bytes_transferred": 5368709120,
    "destination": "mega.nz",
    "protocol": "HTTPS"
  },
  "risk_score": 78,
  "start_time": 1704090000000,
  "status": "in_progress",
  "title": "Data Exfiltration - Cloud Upload",
  "type": "exfil_cloud_storage",
  "update_time": 1704094000000,
  "url": "https://extrahop.example.com/extrahop/#/detections/12347"
}
```

## Parser - Detections Format

### Static Fields

| Field | Value |
| --- | --- |
| **event.kind** | "alert" |
| **event.type** | ["info"] |
| **event.category** | ["intrusion_detection", "network"] |
| **event.module** | "extrahop" |
| **event.dataset** | "extrahop.detections" |
| **observer.vendor** | "ExtraHop" |
| **observer.product** | "Reveal(x)" |
| **observer.type** | "ids" |

### Dynamic Fields - Detections

| Field to extract | ECS field | Comment |
| --- | --- | --- |
| mod_time | **@timestamp** | Convert from ms to ISO 8601 |
| id | **event.id** | Unique detection identifier |
| type | **event.action** | Detection type identifier |
| title | **event.reason** | Detection title |
| description | **message** | Detection description |
| risk_score | **event.risk_score** | Risk score (0-99) |
| categories[0] | **event.category** | Primary category |
| status | **event.outcome** | Map: new/in_progress=success, closed=success |
| url | **event.url** | Link to ExtraHop UI |
| start_time | **event.start** | Detection start time |
| end_time | **event.end** | Detection end time |
| mitre_tactics | **threat.tactic.id** | MITRE tactic IDs |
| mitre_techniques | **threat.technique.id** | MITRE technique IDs |
| participants[role=offender].ipaddr | **source.ip** | Offender IP address |
| participants[role=offender].hostname | **source.hostname** | Offender hostname |
| participants[role=offender].macaddr | **source.mac** | Offender MAC address |
| participants[role=victim].ipaddr | **destination.ip** | Victim IP address |
| participants[role=victim].hostname | **destination.hostname** | Victim hostname |
| participants[role=victim].macaddr | **destination.mac** | Victim MAC address |
| assignee | **user.name** | Assigned analyst |
| appliance_id | **observer.name** | ExtraHop appliance ID |

### ExtraHop-Specific Fields (Detections)

| Field to extract | Custom field | Comment |
| --- | --- | --- |
| id | **extrahop.detection.id** | Detection ID |
| type | **extrahop.detection.type** | Detection type |
| title | **extrahop.detection.title** | Detection title |
| categories | **extrahop.detection.categories** | All categories array |
| risk_score | **extrahop.detection.risk_score** | Risk score |
| status | **extrahop.detection.status** | Detection status |
| resolution | **extrahop.detection.resolution** | Resolution status |
| recommended | **extrahop.detection.recommended** | Recommended for triage |
| recommended_factors | **extrahop.detection.recommended_factors** | Recommendation factors |
| is_user_created | **extrahop.detection.is_user_created** | User-created detection |
| ticket_id | **extrahop.detection.ticket_id** | Ticket ID |
| ticket_url | **extrahop.detection.ticket_url** | Ticket URL |
| properties | **extrahop.detection.properties** | Detection properties |
| participants | **extrahop.detection.participants** | Full participants array |
| mitre_tactics | **extrahop.mitre.tactics** | MITRE tactics |
| mitre_techniques | **extrahop.mitre.techniques** | MITRE techniques |
| start_time | **extrahop.detection.start_time** | Start timestamp |
| end_time | **extrahop.detection.end_time** | End timestamp |
| create_time | **extrahop.detection.create_time** | Creation timestamp |
| mod_time | **extrahop.detection.mod_time** | Modification timestamp |
| update_time | **extrahop.detection.update_time** | Update timestamp |
| appliance_id | **extrahop.appliance_id** | Appliance ID |

### MITRE ATT&CK Mapping

Map ExtraHop detection categories to MITRE ATT&CK:

| ExtraHop Category | MITRE Tactic | Description |
| --- | --- | --- |
| sec.recon | TA0043 (Reconnaissance) | Network scanning, discovery |
| sec.attack | TA0001 (Initial Access) | Initial compromise attempts |
| sec.exploit | TA0002 (Execution) | Exploitation attempts |
| sec.lateral | TA0008 (Lateral Movement) | Internal movement |
| sec.command | TA0011 (Command and Control) | C2 communications |
| sec.exfil | TA0010 (Exfiltration) | Data theft |
| sec.action | TA0040 (Impact) | Actions on objectives |
| sec.ransomware | TA0040 (Impact) | Ransomware activity |
| sec.cryptomining | TA0040 (Impact) | Cryptomining |
| sec.dos | TA0040 (Impact) | Denial of service |

### Risk Score to Severity Mapping

| Risk Score Range | event.severity | Severity Label |
| --- | --- | --- |
| 0-29 | 1 | Low |
| 30-49 | 2 | Medium |
| 50-74 | 3 | High |
| 75-99 | 4 | Critical |

---

# Documentation

## Documentation Structure

Add new entry in:
`documentation/docs/integration/categories/network_detection/extrahop.md`

### Overview Section

```markdown
## Overview

ExtraHop Reveal(x) is a Network Detection and Response (NDR) platform that provides real-time visibility into network traffic and uses machine learning to detect security threats. This integration collects security detections from ExtraHop, including MITRE ATT&CK mappings and risk scoring, to provide comprehensive network-based threat visibility in Sekoia.

The integration provides:
- **Security Detections**: ML-based threat detection with behavioral analysis
- **MITRE ATT&CK Mapping**: Tactics and techniques automatically mapped
- **Risk Scoring**: 0-99 risk scores for prioritization
- **Participant Details**: Source and destination device information
```

### Prerequisites Section

```markdown
## Prerequisites

1. **ExtraHop System**: Active ExtraHop Reveal(x) deployment
2. **API Access**:
   - User account with API key generation privileges
   - "ndr": "full" privilege for security detections
   - "metrics": "full" or higher privilege level
3. **Network Connectivity**: HTTPS access to ExtraHop appliance (port 443)
4. **TLS Certificate**: Valid or trusted certificate configuration
```

### Configuration Section

```markdown
## Configuration

### Step 1: Generate API Key in ExtraHop

1. Log in to ExtraHop Administration settings
2. Navigate to **Access Settings** > **API Access**
3. In "Generate an API Key" section, enter a description
4. Click **Generate** and copy the API key
5. Store the key securely (it cannot be viewed again)

### Step 2: Configure ExtraHop Module in Sekoia

1. Go to **Integrations** > **Intake catalog**
2. Search for "ExtraHop"
3. Click **Create** to add the module
4. Enter module-level configuration:

   **ExtraHop Hostname**: `extrahop.company.com`
   **API Key**: `[your API key]`

5. Click **Save**

### Step 3: Create Detections Connector

1. From the ExtraHop module, click **Add Connector**
2. Select **ExtraHop Detections**
3. Configure:

   **Detection Categories**: Select categories to collect
   **Minimum Risk Score**: 30 (recommended)
   **Detection Statuses**: new, in_progress
   **Polling Interval**: 300 seconds (5 minutes)
   **Intake Key**: [from Sekoia intake]

4. Click **Start** to begin collection

## Troubleshooting

### Authentication Failures (401)

**Symptoms**: "API key is invalid" errors

**Solutions**:
1. Verify API key is correct and not revoked
2. Generate a new API key if needed
3. Confirm user has required privileges
4. Check API key access is enabled in ExtraHop settings

### No Detections Collected

**Symptoms**: Connector running but no events in Sekoia

**Solutions**:
1. Verify ExtraHop has active detections
2. Check detection category filter includes desired categories
3. Lower risk_score_min threshold if needed
4. Verify time range and historical_days settings
5. Confirm NDR module is enabled on ExtraHop

### Rate Limit Errors (429)

**Symptoms**: "Rate limit exceeded" errors

**Solutions**:
1. Connector automatically handles rate limiting with backoff
2. Reduce polling frequency if persistent
3. Contact ExtraHop support for rate limit adjustments
```

### Auto-generated Sections

```markdown
{!_shared_content/operations_center/integrations/generated/extrahop-detections.md!}

{!_shared_content/integration/detection_section.md!}

{!_shared_content/operations_center/detection/generated/suggested_rules_extrahop-detections_do_not_edit_manually.md!}
```

---

# Deliverable

## First Deliverable: automation-library

Pull request on [SEKOIA-IO/automation-library](https://github.com/SEKOIA-IO/automation-library) with:

**Directory Structure:**
```
ExtraHop/
├── main.py
├── manifest.json
├── connector_extrahop_detections.json
├── Dockerfile
├── pyproject.toml
├── poetry.lock
├── CHANGELOG.md
├── logo.png
├── extrahop/
│   ├── __init__.py
│   ├── detections_connector.py
│   ├── metrics.py
│   └── client/
│       ├── __init__.py
│       ├── errors.py
│       └── http_client.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── helpers.py
    ├── test_detections_connector.py
    └── client/
        └── test_http_client.py
```

**Key Files:**

1. **extrahop/__init__.py**: Module and configuration classes
   - `ExtraHopConfiguration(BaseModel)` - Hostname + API key
   - `ExtraHopModule(Module)` - Module class

2. **extrahop/detections_connector.py**: Detections connector
   - `ExtraHopDetectionsConfiguration(DefaultConnectorConfiguration)`
   - `ExtraHopDetectionsConnector(AsyncConnector)`
   - Polling every 5 minutes with mod_time checkpoint
   - 7-day TTL cache for deduplication

3. **extrahop/client/http_client.py**: API client
   - `ExtraHopClient` - Async HTTP client
   - API key authentication
   - `AsyncLimiter(max_rate=1, time_period=1)` - Rate limiting

4. **extrahop/client/errors.py**: Custom exceptions
   - `ExtraHopError`, `ExtraHopAuthError`, `ExtraHopRateLimitError`

5. **extrahop/metrics.py**: Prometheus metrics
   - Detection counters by category and risk level
   - MITRE tactic counters

6. **manifest.json**: Module manifest

7. **connector_extrahop_detections.json**: Connector manifest

8. **Dockerfile**: Python 3.12 base, Poetry dependencies

9. **pyproject.toml**: Dependencies

10. **tests/**: Pytest test suite with ≥85% coverage

## Second Deliverable: intake-formats

Pull request on [SEKOIA-IO/intake-formats](https://github.com/SEKOIA-IO/intake-formats) with:

**Format: ExtraHop Detections**

```
ExtraHop/extrahop-detections/
├── _meta/
│   ├── manifest.json
│   ├── logo.png
│   ├── smart-descriptions/
│   └── fields.yml
├── tests/
│   ├── test_lateral_movement.json
│   ├── test_command_control.json
│   ├── test_exfiltration.json
│   └── test_ransomware.json
└── parser.yml
```

**Custom Fields (fields.yml):**
- `extrahop.detection.*` (id, type, title, risk_score, status, etc.)
- `extrahop.mitre.*` (tactics, techniques)
- `extrahop.appliance_id`

## Third Deliverable: documentation

Pull request on [SEKOIA-IO/documentation](https://github.com/SEKOIA-IO/documentation) with:

```
docs/integration/categories/network_detection/extrahop.md
```

Including:
- Overview section
- Prerequisites
- Step-by-step configuration guide
- Troubleshooting section
- Auto-generated sections inclusion

---

# Blockers & Dependencies

## Critical Blockers

### 1. ExtraHop Test Environment Access (Priority: CRITICAL)
**Status**: ⏳ Pending

**Dependencies:**
- [ ] Test ExtraHop appliance or RevealX 360 access
- [ ] API key with appropriate privileges
- [ ] Sample detection data for testing

**Impact**: Cannot validate connector without test environment

### 2. Logo & Brand Assets (Priority: LOW)
**Status**: ⏳ Pending

**Required:**
- [ ] ExtraHop logo (PNG, 400x400px minimum)
- [ ] Permission to use logo in Sekoia documentation

---

## Success Criteria

### Development Complete When:
- [X] Detections connector fully functional
- [X] Format parsing correctly with MITRE mappings
- [X] Test coverage ≥85%
- [X] Documentation complete
- [X] All validation checks passing
- [X] Pull requests approved and merged

### Production Ready When:
- [X] 7 days of stable operation in test environment
- [X] No authentication errors
- [X] No rate limiting issues
- [X] Deduplication working correctly
- [X] MITRE mappings validated

---

**End of Specification**
