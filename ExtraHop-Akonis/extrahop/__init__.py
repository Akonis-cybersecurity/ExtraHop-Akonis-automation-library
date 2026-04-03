"""
ExtraHop Reveal(x) NDR Module
Connector for ExtraHop security detections and network events.
"""

from pydantic import BaseModel, Field
from sekoia_automation.module import Module


class ExtraHopModuleConfiguration(BaseModel):
    """Module-level configuration for ExtraHop integration."""

    hostname: str = Field(
        ...,
        description="ExtraHop appliance hostname or cloud tenant "
        "(e.g., extrahop.company.com or mytenant.api.cloud.extrahop.com)",
    )
    api_key: str = Field(
        default="",
        description="ExtraHop REST API key (on-prem). Leave empty when using OAuth2.",
        json_schema_extra={"secret": True},
    )
    client_id: str = Field(
        default="",
        description="OAuth2 Client ID for RevealX 360 cloud authentication",
    )
    client_secret: str = Field(
        default="",
        description="OAuth2 Client Secret for RevealX 360 cloud authentication",
        json_schema_extra={"secret": True},
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates when connecting to ExtraHop",
    )

    @property
    def use_oauth2(self) -> bool:
        """True when OAuth2 credentials are provided."""
        return bool(self.client_id and self.client_secret)


class ExtraHopModule(Module):
    """ExtraHop Reveal(x) NDR Module."""

    configuration: ExtraHopModuleConfiguration
