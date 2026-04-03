"""
Base action class for ExtraHop actions.
"""

from functools import cached_property

from sekoia_automation.action import Action

from extrahop import ExtraHopModule
from extrahop.client.http_client import ExtraHopClient


class ExtraHopAction(Action):
    """Base class for all ExtraHop actions."""

    module: ExtraHopModule

    @cached_property
    def client(self) -> ExtraHopClient:
        """Get ExtraHop API client."""
        cfg = self.module.configuration
        return ExtraHopClient(
            hostname=cfg.hostname,
            api_key=cfg.api_key,
            client_id=cfg.client_id,
            client_secret=cfg.client_secret,
            verify_ssl=cfg.verify_ssl,
        )
