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
        return ExtraHopClient(
            hostname=self.module.configuration.hostname,
            api_key=self.module.configuration.api_key,
            verify_ssl=self.module.configuration.verify_ssl,
        )
