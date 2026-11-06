"""
Inter-procedural Taint Analysis Engine.
Tracks sensitive privacy sources (Device IDs, Location, BLE UUID, Wi-Fi BSSID)
to exfiltration sinks (HTTP, Sockets, Local Storage, IPC).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from ..parser.bytecode_analyzer import ClassIR, MethodIR, Instruction
from .callgraph import CallGraph


@dataclass
class TaintSource:
    category: str        # DEVICE_ID, LOCATION, IOT_BLE, IOT_WIFI, SENSOR, CREDENTIAL
    api_pattern: str     # Signature pattern to match
    description: str


@dataclass
class TaintSink:
    category: str        # NETWORK_HTTP, NETWORK_SOCKET, IPC_LEAK, LOG_LEAK, STORAGE_LEAK
    api_pattern: str     # Signature pattern to match
    description: str


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    origin_method: str
    sink_method: str
    variable_path: List[str]
    severity: str        # CRITICAL, HIGH, MEDIUM
    description: str


@dataclass
class TaintReport:
    total_sources_found: int = 0
    total_sinks_found: int = 0
    flows: List[TaintFlow] = field(default_factory=list)

    @property
    def has_critical_leak(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.flows)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_sources_found": self.total_sources_found,
            "total_sinks_found": self.total_sinks_found,
            "total_flows": len(self.flows),
            "flows": [
                {
                    "source_category": f.source.category,
                    "source_api": f.source.api_pattern,
                    "sink_category": f.sink.category,
                    "sink_api": f.sink.api_pattern,
                    "origin_method": f.origin_method,
                    "sink_method": f.sink_method,
                    "severity": f.severity,
                    "description": f.description,
                }
                for f in self.flows
            ],
        }


class TaintEngine:
    """Performs forward taint analysis across class bytecode IR."""

    DEFAULT_SOURCES = [
        # Device Identifiers
        TaintSource("DEVICE_ID", "TelephonyManager.getDeviceId", "IMEI / Unique hardware device identifier"),
        TaintSource("DEVICE_ID", "TelephonyManager.getImei", "Hardware IMEI identifier"),
        TaintSource("DEVICE_ID", "Settings.Secure.getString", "Android ID / Hardware SSAID"),
        TaintSource("DEVICE_ID", "AdvertisingIdClient.getAdvertisingIdInfo", "Google Advertising ID (GAID)"),
        TaintSource("DEVICE_ID", "getMacAddress", "Network interface MAC address"),
        # Location & Sensors
        TaintSource("LOCATION", "LocationManager.getLastKnownLocation", "GPS Geographic coordinates"),
        TaintSource("LOCATION", "Location.getLatitude", "Precise latitude coordinate"),
        TaintSource("LOCATION", "Location.getLongitude", "Precise longitude coordinate"),
        TaintSource("SENSOR", "SensorEvent.values", "Physical motion/accelerometer sensor values"),
        # IoT & Local Connectivity (USENIX '23 Companion App research)
        TaintSource("IOT_BLE", "BluetoothDevice.getAddress", "Peripheral Bluetooth MAC address"),
        TaintSource("IOT_BLE", "BluetoothDevice.getName", "Peripheral Smart Device Name"),
        TaintSource("IOT_BLE", "ScanRecord.getBytes", "BLE Advertisement Raw Beacon Payload"),
        TaintSource("IOT_WIFI", "WifiInfo.getSSID", "Local Wi-Fi Network Name / SSID"),
        TaintSource("IOT_WIFI", "WifiInfo.getBSSID", "Local Router BSSID (Geolocation anchor)"),
        # Credentials & Security Keys
        TaintSource("CREDENTIAL", "KeyStore.getEntry", "Cryptographic key / Secret token"),
        TaintSource("CREDENTIAL", "getAuthToken", "Account authentication token"),
    ]

    DEFAULT_SINKS = [
        # Network Sinks
        TaintSink("NETWORK_HTTP", "HttpURLConnection.connect", "HTTP / HTTPS Network socket transmission"),
        TaintSink("NETWORK_HTTP", "HttpURLConnection.getOutputStream", "HTTP POST payload egress"),
        TaintSink("NETWORK_HTTP", "OkHttpClient.newCall", "OkHttp network request execution"),
        TaintSink("NETWORK_HTTP", "URL.openConnection", "Direct network socket connection"),
        TaintSink("NETWORK_HTTP", "requests.post", "HTTP POST request transmission"),
        TaintSink("NETWORK_HTTP", "requests.get", "HTTP GET query string parameter exfiltration"),
        TaintSink("NETWORK_HTTP", "urllib.request.urlopen", "Network stream upload"),
        TaintSink("NETWORK_SOCKET", "Socket.getOutputStream", "Raw TCP network stream output"),
        # Local & IPC Sinks
        TaintSink("IPC_LEAK", "Context.sendBroadcast", "Broadcast intent to external apps"),
        TaintSink("LOG_LEAK", "Log.d", "System logcat diagnostic leakage"),
        TaintSink("LOG_LEAK", "Log.i", "System logcat telemetry leakage"),
    ]

    def __init__(self, sources: Optional[List[TaintSource]] = None, sinks: Optional[List[TaintSink]] = None):
        self.sources = sources or self.DEFAULT_SOURCES
        self.sinks = sinks or self.DEFAULT_SINKS

    def analyze(self, classes: Dict[str, ClassIR], callgraph: Optional[CallGraph] = None) -> TaintReport:
        report = TaintReport()
        tainted_vars: Dict[str, Set[str]] = {}
        source_origins: Dict[Tuple[str, str], TaintSource] = {}

        # Phase 1: Identify source instructions and seed tainted variables
        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                m_full = m_ir.full_name
                tainted_vars[m_full] = set()

                for inst in m_ir.instructions:
                    matched_source = self._match_source(inst)
                    if matched_source:
                        report.total_sources_found += 1
                        target_var = inst.target or "ret_val"
                        tainted_vars[m_full].add(target_var)
                        source_origins[(m_full, target_var)] = matched_source

        # Phase 2: Intra-procedural propagation within each method
        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                m_full = m_ir.full_name
                t_set = tainted_vars[m_full]

                for inst in m_ir.instructions:
                    if any(op in t_set for op in inst.operands):
                        if inst.target:
                            t_set.add(inst.target)
                            for op in inst.operands:
                                if (m_full, op) in source_origins:
                                    source_origins[(m_full, inst.target)] = source_origins[(m_full, op)]

        # Phase 3: Inter-procedural propagation along call edges
        if callgraph:
            changed = True
            iterations = 0
            while changed and iterations < 5:
                changed = False
                iterations += 1
                for caller, callees in callgraph.edges.items():
                    caller_taints = tainted_vars.get(caller, set())
                    if not caller_taints:
                        continue
                    for callee in callees:
                        callee_taints = tainted_vars.setdefault(callee, set())
                        for var in caller_taints:
                            if var not in callee_taints:
                                callee_taints.add(var)
                                changed = True
                                if (caller, var) in source_origins:
                                    source_origins[(callee, var)] = source_origins[(caller, var)]

        # Phase 4: Identify sinks consuming tainted data
        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                m_full = m_ir.full_name
                t_set = tainted_vars.get(m_full, set())

                for inst in m_ir.instructions:
                    matched_sink = self._match_sink(inst)
                    if matched_sink:
                        report.total_sinks_found += 1
                        tainted_args = [op for op in inst.operands if op in t_set]
                        if tainted_args or not inst.operands or len(t_set) > 0:
                            src = None
                            for op in tainted_args:
                                if (m_full, op) in source_origins:
                                    src = source_origins[(m_full, op)]
                                    break
                            if not src and source_origins:
                                src = list(source_origins.values())[0]

                            if src:
                                severity = "CRITICAL" if matched_sink.category.startswith("NETWORK") else "HIGH"
                                desc = (
                                    f"Sensitive dataflow detected: Source '{src.category}' ({src.api_pattern}) "
                                    f"exfiltrated to Sink '{matched_sink.category}' ({matched_sink.api_pattern}) "
                                    f"in method '{m_full}'."
                                )
                                report.flows.append(TaintFlow(
                                    source=src,
                                    sink=matched_sink,
                                    origin_method=m_full,
                                    sink_method=inst.method_signature or "sink_invocation",
                                    variable_path=tainted_args or ["data"],
                                    severity=severity,
                                    description=desc,
                                ))

        return report

    def _match_source(self, inst: Instruction) -> Optional[TaintSource]:
        sig = inst.method_signature or ""
        field_name = inst.field_name or ""
        for s in self.sources:
            if s.api_pattern in sig or (field_name and s.api_pattern in field_name):
                return s
        return None

    def _match_sink(self, inst: Instruction) -> Optional[TaintSink]:
        sig = inst.method_signature or ""
        for s in self.sinks:
            if s.api_pattern in sig:
                return s
        return None
