"""
ExtraHop Get Device Action

Retrieves details of a network device from ExtraHop by its numeric device ID.
Use this after a detection to enrich context: hostname, IP, role, vendor, criticality.
"""
from traceback import format_exc
from typing import Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from . import ExtraHopModule
from .client import ApiClient
from .client.auth import ExtraHopApiAuthentication


class GetDeviceArguments(BaseModel):
    device_id: int = Field(..., description="Numeric ID of the ExtraHop device")


class GetDeviceResults(BaseModel):
    id: Optional[int] = Field(default=None, description="Device ID")
    display_name: Optional[str] = Field(default=None, description="Device display name")
    ipaddr4: Optional[str] = Field(default=None, description="IPv4 address")
    ipaddr6: Optional[str] = Field(default=None, description="IPv6 address")
    macaddr: Optional[str] = Field(default=None, description="MAC address")
    hostname: Optional[str] = Field(default=None, description="Hostname")
    device_class: Optional[str] = Field(default=None, description="Device class: node, remote, custom")
    role: Optional[str] = Field(default=None, description="Device role: server, client, desktop, etc.")
    vendor: Optional[str] = Field(default=None, description="Hardware vendor")
    critical: Optional[bool] = Field(default=None, description="True if the device is marked as critical")


class GetDeviceAction(Action):
    """Retrieve details of an ExtraHop network device by its numeric ID."""

    module: ExtraHopModule

    def run(self, arguments: GetDeviceArguments) -> GetDeviceResults:
        try:
            base_url = self.module.configuration.tenant_url
            client = ApiClient(
                auth=ExtraHopApiAuthentication(
                    base_url=base_url,
                    client_id=self.module.configuration.client_id,
                    client_secret=self.module.configuration.client_secret,
                )
            )
            url = f"{base_url}api/v1/devices/{arguments.device_id}"
            response = client.get(url, headers={"Accept": "application/json"}, timeout=60)
            response.raise_for_status()

            data = response.json()
            self.log(message=f"Retrieved device {arguments.device_id}", level="info")
            return GetDeviceResults(**data)

        except Exception as error:
            self.log(message=f"Error retrieving device: {error}", level="error")
            self.log(message=format_exc(), level="error")
            self.error(str(error))
