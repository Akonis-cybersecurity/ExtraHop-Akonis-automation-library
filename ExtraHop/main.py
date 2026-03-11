from extrahop import ExtraHopModule
from extrahop.reveal_360_trigger import ExtraHopReveal360Connector
from extrahop.action_get_detection import GetDetectionAction
from extrahop.action_update_detection import UpdateDetectionAction
from extrahop.action_search_detections import SearchDetectionsAction
from extrahop.action_get_device import GetDeviceAction
from extrahop.action_watchlist_add import WatchlistAddAction
from extrahop.action_watchlist_remove import WatchlistRemoveAction

if __name__ == "__main__":
    module = ExtraHopModule()
    # Existing trigger
    module.register(ExtraHopReveal360Connector, "extrahop_reveal_360")
    # Actions
    module.register(GetDetectionAction, "extrahop-get-detection")
    module.register(UpdateDetectionAction, "extrahop-update-detection")
    module.register(SearchDetectionsAction, "extrahop-search-detections")
    module.register(GetDeviceAction, "extrahop-get-device")
    module.register(WatchlistAddAction, "extrahop-watchlist-add")
    module.register(WatchlistRemoveAction, "extrahop-watchlist-remove")
    module.run()
