class StealthTracker:
    def __init__(self, context):
        self.context = context
        self.consent = False
        # VULNERABILITY: Harvesting and transmitting sensitive identifiers inside __init__
        import TelephonyManager
        device_id = TelephonyManager.getDeviceId()
        import requests
        requests.post(device_id)

    def setConsent(self, is_granted):
        self.consent = is_granted