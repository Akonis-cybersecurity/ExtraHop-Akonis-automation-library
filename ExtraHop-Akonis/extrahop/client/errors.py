"""Custom exceptions for ExtraHop API client."""


class ExtraHopAPIError(Exception):
    """Base exception for ExtraHop API errors."""

    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response = response or {}

    def __str__(self) -> str:
        if self.status_code:
            return f"ExtraHopAPIError({self.status_code}): {self.message}"
        return f"ExtraHopAPIError: {self.message}"


class ExtraHopAuthError(ExtraHopAPIError):
    """Authentication error (401/403)."""

    def __str__(self) -> str:
        return f"ExtraHopAuthError({self.status_code}): {self.message}"


class ExtraHopRateLimitError(ExtraHopAPIError):
    """Rate limit exceeded (429)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        status_code: int = 429,
        retry_after: int | None = None,
        response: dict | None = None,
    ):
        super().__init__(message, status_code, response)
        self.retry_after = retry_after

    def __str__(self) -> str:
        if self.retry_after:
            return f"ExtraHopRateLimitError: {self.message} (retry after {self.retry_after}s)"
        return f"ExtraHopRateLimitError: {self.message}"


class ExtraHopNotFoundError(ExtraHopAPIError):
    """Resource not found (404)."""

    def __str__(self) -> str:
        return f"ExtraHopNotFoundError: {self.message}"


class DetectionParsingError(Exception):
    """Error parsing detection data."""

    def __init__(self, message: str, detection_id: int | None = None, raw_data: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detection_id = detection_id
        self.raw_data = raw_data

    def __str__(self) -> str:
        if self.detection_id:
            return f"DetectionParsingError(id={self.detection_id}): {self.message}"
        return f"DetectionParsingError: {self.message}"
