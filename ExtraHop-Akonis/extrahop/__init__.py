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
        description="ExtraHop appliance hostname or IP address (e.g., extrahop.company.com)",
    )
    api_key: str = Field(
        ...,
        description="ExtraHop REST API key generated from Administration settings",
        json_schema_extra={"secret": True},
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates when connecting to ExtraHop",
    )


class ExtraHopModule(Module):
    """ExtraHop Reveal(x) NDR Module."""

    configuration: ExtraHopModuleConfiguration
