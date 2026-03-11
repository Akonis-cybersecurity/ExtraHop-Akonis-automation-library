"""
ExtraHop Update Detection Action

Updates the status, assignee, resolution, or ticket link of an ExtraHop detection.
Useful in SOAR playbooks to acknowledge, close, or escalate detections automatically.
"""
from traceback import format_exc
from typing import Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from . import ExtraHopModule
from .client import ApiClient
from .client.auth import ExtraHopApiAuthentication


class UpdateDetectionArguments(BaseModel):
    detection_id: int = Field(..., description="ID of the detection to update")
    status: Optional[str] = Field(default=None, description="New status: open or closed")
    assignee: Optional[str] = Field(default=None, description="Analyst email to assign the detection to")
    resolution: Optional[str] = Field(
        default=None,
        description="Resolution: action_taken, no_action, or false_positive"
    )
    ticket_url: Optional[str] = Field(default=None, description="URL of the external ticket (e.g. Jira)")
    ticket_id: Optional[str] = Field(default=None, description="External ticket ID (e.g. JIRA-1234)")
    note: Optional[str] = Field(default=None, description="Free-text analyst note to add")


class UpdateDetectionResults(BaseModel):
    success: bool = Field(default=False, description="True if the detection was updated successfully")
    detection_id: int = Field(..., description="ID of the updated detection")


class UpdateDetectionAction(Action):
    """
    Update an ExtraHop detection: change status, assign an analyst,
    link to an external ticket, or add a note.
    """

    module: ExtraHopModule

    def run(self, arguments: UpdateDetectionArguments) -> UpdateDetectionResults:
        try:
            base_url = self.module.configuration.tenant_url
            client = ApiClient(
                auth=ExtraHopApiAuthentication(
                    base_url=base_url,
                    client_id=self.module.configuration.client_id,
                    client_secret=self.module.configuration.client_secret,
                )
            )

            payload: dict = {}
            if arguments.status is not None:
                payload["status"] = arguments.status
            if arguments.assignee is not None:
                payload["assignee"] = arguments.assignee
            if arguments.resolution is not None:
                payload["resolution"] = arguments.resolution
            if arguments.ticket_url is not None:
                payload["ticket_url"] = arguments.ticket_url
            if arguments.ticket_id is not None:
                payload["ticket_id"] = arguments.ticket_id
            if arguments.note is not None:
                payload["note"] = arguments.note

            if not payload:
                self.log(message="No update fields provided — nothing to do.", level="warning")
                return UpdateDetectionResults(success=True, detection_id=arguments.detection_id)

            url = f"{base_url}api/v1/detections/{arguments.detection_id}"
            response = client.patch(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
            response.raise_for_status()

            self.log(message=f"Updated detection {arguments.detection_id}: {list(payload.keys())}", level="info")
            return UpdateDetectionResults(success=True, detection_id=arguments.detection_id)

        except Exception as error:
            self.log(message=f"Error updating detection: {error}", level="error")
            self.log(message=format_exc(), level="error")
            self.error(str(error))
