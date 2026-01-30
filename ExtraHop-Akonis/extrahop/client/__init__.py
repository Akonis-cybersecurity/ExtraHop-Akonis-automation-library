"""ExtraHop API Client package."""

from extrahop.client.errors import (
    ExtraHopAPIError,
    ExtraHopAuthError,
    ExtraHopNotFoundError,
    ExtraHopRateLimitError,
)
from extrahop.client.http_client import ExtraHopClient

__all__ = [
    "ExtraHopClient",
    "ExtraHopAPIError",
    "ExtraHopAuthError",
    "ExtraHopRateLimitError",
    "ExtraHopNotFoundError",
]
