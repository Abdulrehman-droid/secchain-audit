class SuperAdMediation:
    def __init__(self, context):
        self.context = context

    def setConsent(self, granted):
        # Propagates to alpha but drops beta!
        import com_subad_alpha
        com_subad_alpha.setConsent(granted)
