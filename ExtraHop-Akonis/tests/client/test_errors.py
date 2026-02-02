"""Tests for ExtraHop API error classes."""

import pytest

from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopRateLimitError,
    ExtraHopNotFoundError,
    DetectionParsingError,
)


class TestExtraHopAPIError:
    """Tests for ExtraHopAPIError."""

    def test_init_with_message_only(self):
        """Test initialization with message only."""
        error = ExtraHopAPIError("Something went wrong")
        assert error.message == "Something went wrong"
        assert error.status_code is None
        assert error.response == {}

    def test_init_with_all_params(self):
        """Test initialization with all parameters."""
        error = ExtraHopAPIError(
            message="Server error",
            status_code=500,
            response={"error": "Internal error"},
        )
        assert error.message == "Server error"
        assert error.status_code == 500
        assert error.response == {"error": "Internal error"}

    def test_str_with_status_code(self):
        """Test string representation with status code."""
        error = ExtraHopAPIError("Server error", status_code=500)
        assert str(error) == "ExtraHopAPIError(500): Server error"

    def test_str_without_status_code(self):
        """Test string representation without status code."""
        error = ExtraHopAPIError("Unknown error")
        assert str(error) == "ExtraHopAPIError: Unknown error"


class TestExtraHopAuthError:
    """Tests for ExtraHopAuthError."""

    def test_init(self):
        """Test initialization."""
        error = ExtraHopAuthError("Invalid API key", status_code=401)
        assert error.message == "Invalid API key"
        assert error.status_code == 401

    def test_str(self):
        """Test string representation."""
        error = ExtraHopAuthError("Invalid API key", status_code=401)
        assert str(error) == "ExtraHopAuthError(401): Invalid API key"

    def test_str_forbidden(self):
        """Test string representation for forbidden error."""
        error = ExtraHopAuthError("Insufficient privileges", status_code=403)
        assert str(error) == "ExtraHopAuthError(403): Insufficient privileges"


class TestExtraHopRateLimitError:
    """Tests for ExtraHopRateLimitError."""

    def test_init_default(self):
        """Test default initialization."""
        error = ExtraHopRateLimitError()
        assert error.message == "Rate limit exceeded"
        assert error.status_code == 429
        assert error.retry_after is None

    def test_init_with_retry_after(self):
        """Test initialization with retry_after."""
        error = ExtraHopRateLimitError(
            message="Too many requests",
            retry_after=60,
        )
        assert error.message == "Too many requests"
        assert error.retry_after == 60

    def test_str_with_retry_after(self):
        """Test string representation with retry_after."""
        error = ExtraHopRateLimitError(retry_after=30)
        assert str(error) == "ExtraHopRateLimitError: Rate limit exceeded (retry after 30s)"

    def test_str_without_retry_after(self):
        """Test string representation without retry_after."""
        error = ExtraHopRateLimitError()
        assert str(error) == "ExtraHopRateLimitError: Rate limit exceeded"


class TestExtraHopNotFoundError:
    """Tests for ExtraHopNotFoundError."""

    def test_init(self):
        """Test initialization."""
        error = ExtraHopNotFoundError("Detection not found", status_code=404)
        assert error.message == "Detection not found"
        assert error.status_code == 404

    def test_str(self):
        """Test string representation."""
        error = ExtraHopNotFoundError("Resource not found", status_code=404)
        assert str(error) == "ExtraHopNotFoundError: Resource not found"


class TestDetectionParsingError:
    """Tests for DetectionParsingError."""

    def test_init_with_message_only(self):
        """Test initialization with message only."""
        error = DetectionParsingError("Invalid JSON")
        assert error.message == "Invalid JSON"
        assert error.detection_id is None
        assert error.raw_data is None

    def test_init_with_all_params(self):
        """Test initialization with all parameters."""
        error = DetectionParsingError(
            message="Missing required field",
            detection_id=12345,
            raw_data={"id": 12345, "type": None},
        )
        assert error.message == "Missing required field"
        assert error.detection_id == 12345
        assert error.raw_data == {"id": 12345, "type": None}

    def test_str_with_detection_id(self):
        """Test string representation with detection ID."""
        error = DetectionParsingError(
            message="Parse error",
            detection_id=12345,
        )
        assert str(error) == "DetectionParsingError(id=12345): Parse error"

    def test_str_without_detection_id(self):
        """Test string representation without detection ID."""
        error = DetectionParsingError("Parse error")
        assert str(error) == "DetectionParsingError: Parse error"


class TestErrorInheritance:
    """Tests for error inheritance."""

    def test_api_error_is_exception(self):
        """Test that ExtraHopAPIError inherits from Exception."""
        error = ExtraHopAPIError("Test error")
        assert isinstance(error, Exception)

    def test_auth_error_is_api_error(self):
        """Test that ExtraHopAuthError inherits from ExtraHopAPIError."""
        error = ExtraHopAuthError("Auth error", 401)
        assert isinstance(error, ExtraHopAPIError)
        assert isinstance(error, Exception)

    def test_rate_limit_error_is_api_error(self):
        """Test that ExtraHopRateLimitError inherits from ExtraHopAPIError."""
        error = ExtraHopRateLimitError()
        assert isinstance(error, ExtraHopAPIError)

    def test_not_found_error_is_api_error(self):
        """Test that ExtraHopNotFoundError inherits from ExtraHopAPIError."""
        error = ExtraHopNotFoundError("Not found", 404)
        assert isinstance(error, ExtraHopAPIError)

    def test_parsing_error_is_exception(self):
        """Test that DetectionParsingError inherits from Exception."""
        error = DetectionParsingError("Parse error")
        assert isinstance(error, Exception)

    def test_catch_api_error_catches_subclasses(self):
        """Test that catching ExtraHopAPIError catches subclasses."""
        errors = [
            ExtraHopAuthError("Auth error", 401),
            ExtraHopRateLimitError(),
            ExtraHopNotFoundError("Not found", 404),
        ]
        for error in errors:
            try:
                raise error
            except ExtraHopAPIError as e:
                assert e is error
