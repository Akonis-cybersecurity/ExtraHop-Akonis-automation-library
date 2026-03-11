"""
ExtraHop Remove Device from Watchlist Action

Removes a device from the ExtraHop watchlist by IP, MAC address, or device ID.
Use this when an investigation concludes and a device no longer needs special attention.
"""
from traceback import format_exc
from typing import Optional

from pydantic.v1 import BaseModel, Field, validator
from sekoia_automation.action import Action

from . import ExtraHopModule
from .client import ApiClient
from .client.auth import ExtraHopApiAuthentication


class WatchlistRemoveArguments(BaseModel):
    ip_address: Optional[str] = Field(default=None, description="IPv4 or IPv6 address to remove")
    mac_address: Optional[str] = Field(default=None, description="MAC address (aa:bb:cc:dd:ee:ff)")
    device_id: Optional[int] = Field(default=None, description="ExtraHop numeric device ID")

    @validator("device_id", always=True)
    def at_least_one_identifier(cls, v, values):
        if not any([values.get("ip_address"), values.get("mac_address"), v]):
            raise ValueError("At least one of ip_address, mac_address, or device_id must be provided")
        return v


class WatchlistRemoveResults(BaseModel):
    success: bool = Field(default=False, description="True if device was removed from watchlist")
    message: str = Field(default="", description="Result message")


class WatchlistRemoveAction(Action):
    """Remove a device from the ExtraHop watchlist by IP, MAC, or device ID."""

    module: ExtraHopModule

    def run(self, arguments: WatchlistRemoveArguments) -> WatchlistRemoveResults:
        try:
            base_url = self.module.configuration.tenant_url
            client = ApiClient(
                auth=ExtraHopApiAuthentication(
                    base_url=base_url,
                    client_id=self.module.configuration.client_id,
                    client_secret=self.module.configuration.client_secret,
                )
            )

            unassign_entry: dict = {}
            if arguments.ip_address:
                unassign_entry["ipaddr"] = arguments.ip_address
            elif arguments.mac_address:
                unassign_entry["macaddr"] = arguments.mac_address
            elif arguments.device_id:
                unassign_entry["id"] = arguments.device_id

            payload = {"unassign": [unassign_entry]}

            url = f"{base_url}api/v1/watchlist"
            response = client.delete(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
            response.raise_for_status()

            identifier = arguments.ip_address or arguments.mac_address or str(arguments.device_id)
            self.log(message=f"Removed {identifier} from watchlist", level="info")
            return WatchlistRemoveResults(success=True, message=f"Device {identifier} removed from watchlist")

        except Exception as error:
            self.log(message=f"Error removing from watchlist: {error}", level="error")
            self.log(message=format_exc(), level="error")
            self.error(str(error))
