"""Pytest fixtures for ExtraHop connector tests."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def sample_detection():
    """Sample ExtraHop detection."""
    return {
        "id": 12345,
        "type": "lateral_movement_smb",
        "title": "Lateral Movement - SMB/Admin Activity",
        "description": "A device is using administrative credentials to access multiple internal systems via SMB.",
        "categories": ["sec", "sec.lateral"],
        "risk_score": 85,
        "status": "new",
        "resolution": None,
        "assignee": None,
        "start_time": 1704067200000,
        "end_time": None,
        "create_time": 1704067200000,
        "mod_time": 1704071000000,
        "update_time": 1704071000000,
        "mitre_tactics": ["TA0008"],
        "mitre_techniques": ["T1021", "T1021.002"],
        "participants": [
            {
                "id": 1,
                "object_type": "device",
                "object_id": 5678,
                "role": "offender",
                "hostname": "WORKSTATION-01",
                "ipaddr": "192.168.1.100",
                "macaddr": "00:1A:2B:3C:4D:5E",
            },
            {
                "id": 2,
                "object_type": "device",
                "object_id": 5679,
                "role": "victim",
                "hostname": "SERVER-DC01",
                "ipaddr": "192.168.1.10",
                "macaddr": "00:1A:2B:3C:4D:5F",
            },
        ],
        "properties": {
            "unique_hosts": 23,
            "admin_shares_accessed": ["C$", "ADMIN$"],
        },
        "appliance_id": 1,
        "is_user_created": False,
        "recommended": True,
        "recommended_factors": ["high_risk_score"],
        "url": "https://extrahop.example.com/extrahop/#/detections/12345",
    }


@pytest.fixture
def sample_detection_c2():
    """Sample C2 detection."""
    return {
        "id": 12346,
        "type": "c2_dns_tunnel",
        "title": "Command and Control - Suspicious DNS Activity",
        "description": "Device communicating with known malicious domain using encrypted DNS over HTTPS.",
        "categories": ["sec", "sec.command"],
        "risk_score": 92,
        "status": "new",
        "resolution": None,
        "assignee": None,
        "start_time": 1704080000000,
        "end_time": None,
        "create_time": 1704080000000,
        "mod_time": 1704082000000,
        "update_time": 1704082000000,
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071", "T1071.001", "T1573"],
        "participants": [
            {
                "id": 1,
                "object_type": "device",
                "object_id": 6789,
                "role": "offender",
                "hostname": "LAPTOP-DEV-03",
                "ipaddr": "192.168.20.50",
                "macaddr": "00:2B:3C:4D:5E:6F",
            },
        ],
        "properties": {
            "domain": "malicious-c2.example.com",
            "protocol": "DNS over HTTPS",
            "request_count": 150,
        },
        "appliance_id": 1,
        "is_user_created": False,
        "url": "https://extrahop.example.com/extrahop/#/detections/12346",
    }


@pytest.fixture
def sample_detection_exfil():
    """Sample data exfiltration detection."""
    return {
        "id": 12347,
        "type": "exfil_cloud_storage",
        "title": "Data Exfiltration - Cloud Upload",
        "description": "Unusual volume of data being transferred to external cloud storage service.",
        "categories": ["sec", "sec.exfil"],
        "risk_score": 78,
        "status": "in_progress",
        "resolution": None,
        "assignee": "security_analyst",
        "start_time": 1704090000000,
        "end_time": 1704093600000,
        "create_time": 1704090000000,
        "mod_time": 1704094000000,
        "update_time": 1704094000000,
        "mitre_tactics": ["TA0010"],
        "mitre_techniques": ["T1567", "T1567.002"],
        "participants": [
            {
                "id": 1,
                "object_type": "device",
                "object_id": 7890,
                "role": "offender",
                "hostname": "FILESERVER-01",
                "ipaddr": "192.168.5.20",
                "macaddr": "00:3C:4D:5E:6F:70",
            },
        ],
        "properties": {
            "bytes_transferred": 5368709120,
            "destination": "mega.nz",
            "protocol": "HTTPS",
        },
        "appliance_id": 1,
        "is_user_created": False,
        "url": "https://extrahop.example.com/extrahop/#/detections/12347",
    }


@pytest.fixture
def sample_audit_log():
    """Sample audit log entry."""
    return {
        "id": 1001,
        "time": 1704100000000,
        "occur_time": 1704100000000,
        "body": {
            "action": "user_login",
            "user": "admin",
            "detail": "User logged in from 10.0.0.1",
        },
    }


@pytest.fixture
def sample_device():
    """Sample device object."""
    return {
        "id": 5678,
        "display_name": "WORKSTATION-01",
        "ipaddr4": "192.168.1.100",
        "macaddr": "00:1A:2B:3C:4D:5E",
        "device_class": "node",
        "role": "workstation",
        "vendor": "Dell",
        "is_l3": True,
        "activity": ["smb_client", "rdp_client"],
    }


@pytest.fixture
def sample_detection_formats():
    """Sample detection formats."""
    return [
        {
            "type": "lateral_movement_smb",
            "display_name": "Lateral Movement - SMB/Admin Activity",
            "category": "sec.lateral",
            "description": "Detects suspicious SMB administrative share access patterns.",
        },
        {
            "type": "c2_dns_tunnel",
            "display_name": "Command and Control - DNS Tunneling",
            "category": "sec.command",
            "description": "Detects potential DNS tunneling for C2 communication.",
        },
        {
            "type": "exfil_cloud_storage",
            "display_name": "Data Exfiltration - Cloud Storage",
            "category": "sec.exfil",
            "description": "Detects large data transfers to cloud storage services.",
        },
    ]


@pytest.fixture
def mock_module_configuration():
    """Mock module configuration."""
    return {
        "hostname": "extrahop.example.com",
        "api_key": "test-api-key-12345",
        "verify_ssl": True,
    }


@pytest.fixture
def mock_connector_configuration():
    """Mock connector configuration."""
    return {
        "intake_key": "test-intake-key",
        "intake_server": "https://intake.sekoia.io",
        "detection_categories": ["sec", "sec.lateral", "sec.command"],
        "min_risk_score": 30,
        "detection_statuses": ["new", "in_progress"],
        "polling_frequency_minutes": 5,
        "historical_days": 7,
        "batch_size": 1000,
        "include_audit_logs": False,
    }
