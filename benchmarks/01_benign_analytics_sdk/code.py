class CleanAnalytics:
    def __init__(self, app_context):
        self.context = app_context
        self.consent_granted = False
        self.event_queue = []

    def setConsent(self, granted):
        self.consent_granted = granted

    def logEvent(self, event_name):
        if self.consent_granted:
            payload = event_name
            import requests
            requests.post(payload)
        else:
            self.event_queue.append(event_name)