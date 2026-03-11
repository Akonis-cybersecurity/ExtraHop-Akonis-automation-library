"""
ExtraHop Get Detection Action

Retrieves the full details of a single ExtraHop detection by its ID.
"""
from traceback import format_exc
from typing import Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from . import ExtraHopModule
from .client import ApiClient
from .client.auth import ExtraHopApiAuthentication


class GetDetectionArguments(BaseModel):
    detection_id: int = Field(..., description="ID of the ExtraHop detection to retrieve")


class GetDetectionResults(BaseModel):
    id: Optional[int] = Field(default=None, description="Detection ID")
    title: Optional[str] = Field(default=None, description="Detection title")
    description: Optional[str] = Field(default=None, description="Detection description")
    risk_score: Optional[float] = Field(default=None, description="Risk score (0–100)")
    status: Optional[str] = Field(default=None, description="Status: open or closed")
    assignee: Optional[str] = Field(default=None, description="Assigned analyst email")
    start_time: Optional[int] = Field(default=None, description="Start time (epoch ms)")
    end_time: Optional[int] = Field(default=None, description="End time (epoch ms)")
    resolution: Optional[str] = Field(default=None, description="Resolution: action_taken, no_action, false_positive")
    ticket_url: Optional[str] = Field(default=None, description="URL of the linked external ticket")


class GetDetectionAction(Action):
    """Retrieve a single ExtraHop detection by its numeric ID."""

    module: ExtraHopModule

    def run(self, arguments: GetDetectionArguments) -> GetDetectionResults:
        try:
            base_url = self.module.configuration.tenant_url
            client = ApiClient(
                auth=ExtraHopApiAuthentication(
                    base_url=base_url,
                    client_id=self.module.configuration.client_id,
                    client_secret=self.module.configuration.client_secret,
                )
            )
            url = f"{base_url}api/v1/detections/{arguments.detection_id}"
            response = client.get(url, headers={"Accept": "application/json"}, timeout=60)
            response.raise_for_status()

            data = response.json()
            self.log(message=f"Retrieved detection {arguments.detection_id}", level="info")
            return GetDetectionResults(**data)

        except Exception as error:
            self.log(message=f"Error retrieving detection: {error}", level="error")
            self.log(message=format_exc(), level="error")
            self.error(str(error))
