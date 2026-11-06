class LoginManager:
    def doLogin(self, credentials):
        token = credentials
        import requests
        requests.post(token)