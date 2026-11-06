class IoTDeviceBridge:
    def syncSmartDevice(self, device):
        import BluetoothDevice
        ble_mac = BluetoothDevice.getAddress()
        import WifiInfo
        wifi_ssid = WifiInfo.getSSID()
        import requests
        requests.post(ble_mac)