"""
ExtraHop Search Detections Action

Searches ExtraHop detections using the POST /detections/search endpoint.
Supports filtering by time range, status, assignee, and risk score.
Returns a list of matching detections usable in downstream playbook steps.
"""
import time
from traceback import format_exc
from typing import Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from . import ExtraHopModule
from .client import ApiClient
from .client.auth import ExtraHopApiAuthentication


class SearchDetectionsArguments(BaseModel):
    from_time: Optional[int] = Field(
        default=None,
        description="Search window start (epoch milliseconds). Defaults to 24h ago."
    )
    until_time: Optional[int] = Field(
        default=None,
        description="Search window end (epoch milliseconds). Defaults to now."
    )
    limit: int = Field(default=100, description="Max number of detections to return (max 200)")
    status: Optional[str] = Field(default=None, description="Filter by status: open or closed")
    assignee: Optional[str] = Field(default=None, description="Filter by assignee email")
    min_risk_score: Optional[int] = Field(default=None, description="Minimum risk score (0–100)")


class SearchDetectionsResults(BaseModel):
    detections: list = Field(default_factory=list, description="List of detection objects")
    total: int = Field(default=0, description="Total number of matching detections returned")


class SearchDetectionsAction(Action):
    """
    Search ExtraHop detections by time range, status, assignee, or risk score.
    Use this in playbooks to find all open high-risk detections for a given window.
    """

    module: ExtraHopModule

    def run(self, arguments: SearchDetectionsArguments) -> SearchDetectionsResults:
        try:
            base_url = self.module.configuration.tenant_url
            client = ApiClient(
                auth=ExtraHopApiAuthentication(
                    base_url=base_url,
                    client_id=self.module.configuration.client_id,
                    client_secret=self.module.configuration.client_secret,
                )
            )

            now_ms = int(time.time() * 1000)
            from_time = arguments.from_time or (now_ms - 24 * 60 * 60 * 1000)
            until_time = arguments.until_time or now_ms

            payload: dict = {
                "from": from_time,
                "until": until_time,
                "limit": min(arguments.limit, 200),
                "sort": [{"direction": "desc", "field": "risk_score"}],
            }

            filter_rules: list[dict] = []
            if arguments.status:
                filter_rules.append({"field": "status", "operand": arguments.status, "operator": "="})
            if arguments.assignee:
                filter_rules.append({"field": "assignee", "operand": arguments.assignee, "operator": "="})
            if arguments.min_risk_score is not None:
                filter_rules.append({
                    "field": "risk_score",
                    "operand": str(arguments.min_risk_score),
                    "operator": ">="
                })

            if filter_rules:
                payload["filter"] = {"rules": filter_rules, "operator": "and"}

            url = f"{base_url}api/v1/detections/search"
            response = client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=60,
            )
            response.raise_for_status()

            detections = response.json() or []
            self.log(message=f"Found {len(detections)} detections", level="info")
            return SearchDetectionsResults(detections=detections, total=len(detections))

        except Exception as error:
            self.log(message=f"Error searching detections: {error}", level="error")
            self.log(message=format_exc(), level="error")
            self.error(str(error))
