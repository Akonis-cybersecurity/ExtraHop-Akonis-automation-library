"""
ExtraHop device management actions.
Actions for querying and retrieving device information.
"""

import asyncio
from typing import Any

from extrahop.action import ExtraHopAction
from extrahop.client.errors import ExtraHopAPIError, ExtraHopAuthError, ExtraHopNotFoundError


class GetDeviceAction(ExtraHopAction):
    """Get detailed information about a specific device."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        device_id: int = arguments["device_id"]

        self.log(f"Getting device {device_id}")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.get_device(device_id=device_id)
            )
            self.log(f"Successfully retrieved device {device_id}")
            return {"success": True, "device": result}

        except ExtraHopNotFoundError:
            self.error(f"Device {device_id} not found")
            return {"success": False, "error": f"Device {device_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class SearchDevicesAction(ExtraHopAction):
    """Search for devices by IP address, hostname, or MAC address."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        ip_address: str | None = arguments.get("ip_address")
        hostname: str | None = arguments.get("hostname")
        mac_address: str | None = arguments.get("mac_address")
        limit: int = arguments.get("limit", 100)

        # Build filter
        filter_obj: dict[str, Any] = {}

        if ip_address:
            filter_obj["ipaddr"] = ip_address
            self.log(f"Searching devices by IP: {ip_address}")
        elif hostname:
            filter_obj["name"] = hostname
            self.log(f"Searching devices by hostname: {hostname}")
        elif mac_address:
            filter_obj["macaddr"] = mac_address
            self.log(f"Searching devices by MAC: {mac_address}")
        else:
            self.error("At least one search criteria (ip_address, hostname, or mac_address) is required")
            return {
                "success": False,
                "error": "At least one search criteria is required",
            }

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.search_devices(
                    filter_obj=filter_obj,
                    limit=limit,
                )
            )
            self.log(f"Found {len(result)} devices")
            return {"success": True, "devices": result, "count": len(result)}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class SearchRecordsAction(ExtraHopAction):
    """Search for network records (flows, transactions) within a time range."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        from_time: int = arguments["from_time"]
        until_time: int = arguments["until_time"]
        record_types: list[str] | None = arguments.get("record_types")
        ip_address: str | None = arguments.get("ip_address")
        limit: int = arguments.get("limit", 1000)

        self.log(f"Searching records from {from_time} to {until_time}")

        # Build filter if IP provided
        filter_obj: dict[str, Any] | None = None
        if ip_address:
            filter_obj = {
                "field": "ipaddr",
                "operand": ip_address,
                "operator": "=",
            }

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.search_records(
                    from_time=from_time,
                    until_time=until_time,
                    types=record_types,
                    filter_obj=filter_obj,
                    limit=limit,
                )
            )
            self.log(f"Found {len(result)} records")
            return {"success": True, "records": result, "count": len(result)}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}
