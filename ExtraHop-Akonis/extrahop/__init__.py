"""
ExtraHop Reveal(x) NDR Module
Connector for ExtraHop security detections and network events.
"""

from pydantic.v1 import BaseModel
from sekoia_automation.module import Module


class ExtraHopModuleConfiguration(BaseModel):
    """Module-level configuration for ExtraHop integration."""

    hostname: str = ""
    api_key: str = ""
    client_id: str = ""
    client_secret: str = ""
    verify_ssl: bool = True

    @property
    def use_oauth2(self) -> bool:
        """True when OAuth2 credentials are provided."""
        return bool(self.client_id and self.client_secret)


class ExtraHopModule(Module):
    """ExtraHop Reveal(x) NDR Module."""

    configuration: ExtraHopModuleConfiguration
