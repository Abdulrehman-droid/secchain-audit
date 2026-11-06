# SecChain-Audit Empirical Measurement Report

## Executive Summary
- **Total Packages Scanned**: 5
- **Duress Collision Vulnerability Rate**: 20.0% (1/5)
- **PICO Compliance Violation Rate**: 40.0% (2/5)
- **Time-of-Init (TOI-TOC) Leaking Packages**: 1
- **Mediation Wrapper-Drop Packages**: 1
- **Total Sensitive Dataflow Leaks Detected**: 2
- **Corpus Mean Risk Score**: 2.17 / 10.0

## Detailed Package Findings

| Package Name | Risk Score | Duress Hazards | PICO Violations | Taint Leaks | Key Vulnerability |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `com.clean.analytics` | **0.0** | 0 | 0 | 0 | None (Clean) |
| `com.target.bankapp` | **7.2** | 2 | 0 | 0 | Critical Resource Collision (Duress) |
| `com.stealth.tracker` | **1.8** | 0 | 1 | 1 | Time-of-Init to Time-of-Config (TOI-TOC) Leak |
| `com.smarthome.bulbapp` | **0.8** | 0 | 0 | 1 | Sensitive Taint Leak (IOT_BLE) |
| `com.mediation.superad` | **1.0** | 0 | 1 | 0 | Mediation Wrapper Consent Drop |

## Actionable Mitigations
1. **Resource Namespacing**: Implement `android.namespacing=true` in Gradle to isolate third-party library resources.
2. **Deferred Initialization**: Enforce that SDK background telemetry tasks wait for explicit user consent signals.
3. **Mediation Synchronization**: Audit wrapper SDKs to ensure privacy configurations strictly fan-out to all underlying providers.