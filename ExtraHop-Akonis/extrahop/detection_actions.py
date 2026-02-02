"""
ExtraHop detection management actions.
Actions for updating detection status, assignee, resolution, and ticket linking.
"""

import asyncio
from typing import Any

from extrahop.action import ExtraHopAction
from extrahop.client.errors import ExtraHopAPIError, ExtraHopAuthError, ExtraHopNotFoundError


class UpdateDetectionStatusAction(ExtraHopAction):
    """Update the status of a detection."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]
        status: str = arguments["status"]

        self.log(f"Updating detection {detection_id} status to '{status}'")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.update_detection(
                    detection_id=detection_id,
                    status=status,
                )
            )
            self.log(f"Successfully updated detection {detection_id}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class AssignDetectionAction(ExtraHopAction):
    """Assign a detection to a user."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]
        assignee: str = arguments["assignee"]

        self.log(f"Assigning detection {detection_id} to '{assignee}'")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.update_detection(
                    detection_id=detection_id,
                    assignee=assignee,
                )
            )
            self.log(f"Successfully assigned detection {detection_id} to {assignee}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class CloseDetectionAction(ExtraHopAction):
    """Close a detection with optional resolution."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]
        resolution: str = arguments.get("resolution", "action_taken")

        self.log(f"Closing detection {detection_id} with resolution '{resolution}'")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.update_detection(
                    detection_id=detection_id,
                    status="closed",
                    resolution=resolution,
                )
            )
            self.log(f"Successfully closed detection {detection_id}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class AcknowledgeDetectionAction(ExtraHopAction):
    """Acknowledge a detection."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]

        self.log(f"Acknowledging detection {detection_id}")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.update_detection(
                    detection_id=detection_id,
                    status="acknowledged",
                )
            )
            self.log(f"Successfully acknowledged detection {detection_id}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class LinkTicketToDetectionAction(ExtraHopAction):
    """Link an external ticket to a detection."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]
        ticket_id: str = arguments["ticket_id"]
        ticket_url: str = arguments.get("ticket_url", "")

        self.log(f"Linking ticket {ticket_id} to detection {detection_id}")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.update_detection(
                    detection_id=detection_id,
                    ticket_id=ticket_id,
                    ticket_url=ticket_url if ticket_url else None,
                )
            )
            self.log(f"Successfully linked ticket {ticket_id} to detection {detection_id}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}


class GetDetectionAction(ExtraHopAction):
    """Get detailed information about a specific detection."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        detection_id: int = arguments["detection_id"]

        self.log(f"Getting detection {detection_id}")

        try:
            result = asyncio.get_event_loop().run_until_complete(
                self.client.get_detection(detection_id=detection_id)
            )
            self.log(f"Successfully retrieved detection {detection_id}")
            return {"success": True, "detection": result}

        except ExtraHopNotFoundError:
            self.error(f"Detection {detection_id} not found")
            return {"success": False, "error": f"Detection {detection_id} not found"}

        except ExtraHopAuthError as e:
            self.error(f"Authentication error: {e}")
            return {"success": False, "error": str(e)}

        except ExtraHopAPIError as e:
            self.error(f"API error: {e}")
            return {"success": False, "error": str(e)}
