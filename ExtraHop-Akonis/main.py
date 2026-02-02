"""
ExtraHop Reveal(x) NDR Module - Main entry point.
"""

from extrahop import ExtraHopModule
from extrahop.detections_connector import ExtraHopDetectionsConnector

# Detection actions
from extrahop.detection_actions import (
    AcknowledgeDetectionAction,
    AssignDetectionAction,
    CloseDetectionAction,
    GetDetectionAction,
    LinkTicketToDetectionAction,
    UpdateDetectionStatusAction,
)

# Device actions
from extrahop.device_actions import (
    GetDeviceAction,
    SearchDevicesAction,
    SearchRecordsAction,
)

if __name__ == "__main__":
    module = ExtraHopModule()

    # Register connector
    module.register(ExtraHopDetectionsConnector, "extrahop_detections_connector")

    # Register detection actions
    module.register(UpdateDetectionStatusAction, "update_detection_status")
    module.register(AssignDetectionAction, "assign_detection")
    module.register(CloseDetectionAction, "close_detection")
    module.register(AcknowledgeDetectionAction, "acknowledge_detection")
    module.register(LinkTicketToDetectionAction, "link_ticket")
    module.register(GetDetectionAction, "get_detection")

    # Register device actions
    module.register(GetDeviceAction, "get_device")
    module.register(SearchDevicesAction, "search_devices")
    module.register(SearchRecordsAction, "search_records")

    module.run()
