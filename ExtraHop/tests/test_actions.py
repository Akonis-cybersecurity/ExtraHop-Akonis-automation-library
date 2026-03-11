"""
Unit tests for ExtraHop Sekoia.io actions.

Tests use requests-mock to intercept HTTP calls so no real ExtraHop instance is needed.
"""
import pytest
import requests_mock as requests_mock_module
from unittest.mock import MagicMock, patch

from extrahop.action_get_detection import GetDetectionAction, GetDetectionArguments
from extrahop.action_update_detection import UpdateDetectionAction, UpdateDetectionArguments
from extrahop.action_search_detections import SearchDetectionsAction, SearchDetectionsArguments
from extrahop.action_get_device import GetDeviceAction, GetDeviceArguments
from extrahop.action_watchlist_add import WatchlistAddAction, WatchlistAddArguments
from extrahop.action_watchlist_remove import WatchlistRemoveAction, WatchlistRemoveArguments


# ─── Fixtures ──────────────────────────────────────────────────────────────────

BASE_URL = "https://demo.extrahop.com/"
TOKEN_URL = f"{BASE_URL}oauth2/token"
FAKE_TOKEN = "fake-access-token"


def make_mock_module():
    """Return a mock ExtraHop module with standard configuration."""
    module = MagicMock()
    module.configuration.base_url = BASE_URL
    module.configuration.client_id = "test-client-id"
    module.configuration.client_secret = "test-client-secret"
    module.configuration.tenant_url = BASE_URL
    return module


def make_action(action_class):
    """Instantiate an action with a mocked module."""
    action = action_class()
    action.module = make_mock_module()
    action.log = MagicMock()
    action.error = MagicMock()
    return action


@pytest.fixture
def token_response():
    """OAuth2 token response dict."""
    return {
        "access_token": FAKE_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


# ─── Get Detection ─────────────────────────────────────────────────────────────

class TestGetDetectionAction:

    def test_get_detection_success(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.get(
            f"{BASE_URL}api/v1/detections/42",
            json={
                "id": 42,
                "title": "SSH Brute Force",
                "description": "Multiple failed SSH logins",
                "risk_score": 85.0,
                "status": "open",
                "assignee": "analyst@company.com",
                "start_time": 1700000000000,
                "end_time": 1700003600000,
                "resolution": None,
                "ticket_url": None,
            },
        )
        action = make_action(GetDetectionAction)
        result = action.run(GetDetectionArguments(detection_id=42))

        assert result.id == 42
        assert result.title == "SSH Brute Force"
        assert result.risk_score == 85.0
        assert result.status == "open"
        action.error.assert_not_called()

    def test_get_detection_not_found(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.get(f"{BASE_URL}api/v1/detections/999", status_code=404)

        action = make_action(GetDetectionAction)
        action.run(GetDetectionArguments(detection_id=999))

        action.error.assert_called_once()

    def test_get_detection_auth_token_used(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        detection_mock = requests_mock.get(
            f"{BASE_URL}api/v1/detections/1",
            json={"id": 1, "title": "Test", "risk_score": 0.0, "status": "open"},
        )
        action = make_action(GetDetectionAction)
        action.run(GetDetectionArguments(detection_id=1))

        assert detection_mock.called
        assert "Authorization" in detection_mock.last_request.headers
        assert FAKE_TOKEN in detection_mock.last_request.headers["Authorization"]


# ─── Update Detection ──────────────────────────────────────────────────────────

class TestUpdateDetectionAction:

    def test_update_detection_close(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        patch_mock = requests_mock.patch(
            f"{BASE_URL}api/v1/detections/10",
            status_code=204,
        )
        action = make_action(UpdateDetectionAction)
        result = action.run(UpdateDetectionArguments(
            detection_id=10,
            status="closed",
            resolution="action_taken",
        ))

        assert result.success is True
        assert result.detection_id == 10
        assert patch_mock.called
        body = patch_mock.last_request.json()
        assert body["status"] == "closed"
        assert body["resolution"] == "action_taken"

    def test_update_detection_assign_ticket(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.patch(f"{BASE_URL}api/v1/detections/5", status_code=204)

        action = make_action(UpdateDetectionAction)
        result = action.run(UpdateDetectionArguments(
            detection_id=5,
            assignee="soc@company.com",
            ticket_url="https://jira.company.com/TICKET-999",
            ticket_id="TICKET-999",
        ))

        assert result.success is True

    def test_update_detection_no_fields(self, requests_mock, token_response):
        """When no fields given, skip the API call and return success."""
        requests_mock.post(TOKEN_URL, json=token_response)
        action = make_action(UpdateDetectionAction)
        result = action.run(UpdateDetectionArguments(detection_id=7))

        assert result.success is True
        # No PATCH call should have been made
        assert not any(r.method == "PATCH" for r in requests_mock.request_history)

    def test_update_detection_http_error(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.patch(f"{BASE_URL}api/v1/detections/3", status_code=403)

        action = make_action(UpdateDetectionAction)
        action.run(UpdateDetectionArguments(detection_id=3, status="closed"))

        action.error.assert_called_once()


# ─── Search Detections ─────────────────────────────────────────────────────────

class TestSearchDetectionsAction:

    def test_search_returns_list(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        detections = [
            {"id": 1, "title": "Port Scan", "risk_score": 70.0, "status": "open"},
            {"id": 2, "title": "Data Exfil", "risk_score": 95.0, "status": "open"},
        ]
        requests_mock.post(f"{BASE_URL}api/v1/detections/search", json=detections)

        action = make_action(SearchDetectionsAction)
        result = action.run(SearchDetectionsArguments(status="open", limit=50))

        assert result.total == 2
        assert len(result.detections) == 2
        assert result.detections[0]["id"] == 1

    def test_search_with_risk_filter(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        search_mock = requests_mock.post(f"{BASE_URL}api/v1/detections/search", json=[])

        action = make_action(SearchDetectionsAction)
        action.run(SearchDetectionsArguments(min_risk_score=80))

        body = search_mock.last_request.json()
        rules = body["filter"]["rules"]
        risk_rule = next(r for r in rules if r["field"] == "risk_score")
        assert risk_rule["operand"] == "80"
        assert risk_rule["operator"] == ">="

    def test_search_empty_result(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.post(f"{BASE_URL}api/v1/detections/search", json=[])

        action = make_action(SearchDetectionsAction)
        result = action.run(SearchDetectionsArguments())

        assert result.total == 0
        assert result.detections == []

    def test_search_limit_capped_at_200(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        mock = requests_mock.post(f"{BASE_URL}api/v1/detections/search", json=[])

        action = make_action(SearchDetectionsAction)
        action.run(SearchDetectionsArguments(limit=500))

        body = mock.last_request.json()
        assert body["limit"] == 200


# ─── Get Device ────────────────────────────────────────────────────────────────

class TestGetDeviceAction:

    def test_get_device_success(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.get(
            f"{BASE_URL}api/v1/devices/100",
            json={
                "id": 100,
                "display_name": "server01",
                "ipaddr4": "10.0.0.100",
                "macaddr": "aa:bb:cc:dd:ee:ff",
                "hostname": "server01.local",
                "device_class": "node",
                "role": "server",
                "vendor": "Dell",
                "critical": True,
            },
        )
        action = make_action(GetDeviceAction)
        result = action.run(GetDeviceArguments(device_id=100))

        assert result.id == 100
        assert result.hostname == "server01.local"
        assert result.critical is True
        assert result.ipaddr4 == "10.0.0.100"

    def test_get_device_not_found(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.get(f"{BASE_URL}api/v1/devices/9999", status_code=404)

        action = make_action(GetDeviceAction)
        action.run(GetDeviceArguments(device_id=9999))

        action.error.assert_called_once()


# ─── Watchlist Add ─────────────────────────────────────────────────────────────

class TestWatchlistAddAction:

    def test_add_by_ip(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        mock = requests_mock.post(f"{BASE_URL}api/v1/watchlist", status_code=200)

        action = make_action(WatchlistAddAction)
        result = action.run(WatchlistAddArguments(ip_address="192.168.1.50"))

        assert result.success is True
        assert "192.168.1.50" in result.message
        body = mock.last_request.json()
        assert body["assign"][0]["ipaddr"] == "192.168.1.50"

    def test_add_by_mac(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        mock = requests_mock.post(f"{BASE_URL}api/v1/watchlist", status_code=200)

        action = make_action(WatchlistAddAction)
        result = action.run(WatchlistAddArguments(mac_address="aa:bb:cc:dd:ee:ff"))

        assert result.success is True
        body = mock.last_request.json()
        assert body["assign"][0]["macaddr"] == "aa:bb:cc:dd:ee:ff"

    def test_add_requires_identifier(self):
        """Must provide at least one identifier."""
        from pydantic.v1 import ValidationError
        with pytest.raises(ValidationError):
            WatchlistAddArguments()

    def test_add_http_error(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.post(f"{BASE_URL}api/v1/watchlist", status_code=500)

        action = make_action(WatchlistAddAction)
        action.run(WatchlistAddArguments(ip_address="10.0.0.1"))

        action.error.assert_called_once()


# ─── Watchlist Remove ──────────────────────────────────────────────────────────

class TestWatchlistRemoveAction:

    def test_remove_by_ip(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        mock = requests_mock.delete(f"{BASE_URL}api/v1/watchlist", status_code=200)

        action = make_action(WatchlistRemoveAction)
        result = action.run(WatchlistRemoveArguments(ip_address="192.168.1.50"))

        assert result.success is True
        body = mock.last_request.json()
        assert body["unassign"][0]["ipaddr"] == "192.168.1.50"

    def test_remove_by_device_id(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        mock = requests_mock.delete(f"{BASE_URL}api/v1/watchlist", status_code=200)

        action = make_action(WatchlistRemoveAction)
        result = action.run(WatchlistRemoveArguments(device_id=42))

        assert result.success is True
        body = mock.last_request.json()
        assert body["unassign"][0]["id"] == 42

    def test_remove_requires_identifier(self):
        from pydantic.v1 import ValidationError
        with pytest.raises(ValidationError):
            WatchlistRemoveArguments()

    def test_remove_http_error(self, requests_mock, token_response):
        requests_mock.post(TOKEN_URL, json=token_response)
        requests_mock.delete(f"{BASE_URL}api/v1/watchlist", status_code=403)

        action = make_action(WatchlistRemoveAction)
        action.run(WatchlistRemoveArguments(ip_address="10.0.0.2"))

        action.error.assert_called_once()
