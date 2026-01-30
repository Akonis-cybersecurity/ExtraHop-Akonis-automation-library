"""
ExtraHop Reveal(x) NDR Module - Main entry point.
"""

from sekoia_automation.module import Module

from extrahop import ExtraHopModule
from extrahop.detections_connector import ExtraHopDetectionsConnector

if __name__ == "__main__":
    module = ExtraHopModule()
    module.register(ExtraHopDetectionsConnector, "extrahop_detections_connector")
    module.run()
