# SecChain-Audit

Static analysis and measurement framework for Android and IoT supply chain security.

SecChain-Audit identifies architectural integration vulnerabilities in multi-tier mobile SDKs and companion apps. It specifically tests for duplicate resource collisions during compilation and verifies privacy compliance state machines.

---

## Background

Third-party libraries introduce structural risks that standard static analyzers miss:

1. **Resource Collision (Duress, USENIX Security 2023)**:
   AAPT2 flattens resource files into a single namespace. If a transitive library defines an existing resource name (such as `@string/auth_api_endpoint` or `@xml/network_security_config`), the build system resolves the conflict by precedence order. An attacker-controlled package can silently replace backend URLs or enable cleartext traffic without changing Java bytecode.

2. **Privacy API Bypasses (PICO, USENIX Security 2024)**:
   Many advertising and tracking SDKs provide consent APIs (`setConsent()`, `setOptOut()`). In practice, two implementation flaws break compliance:
   - **Time-of-Init (TOI-TOC) Leaks**: Background threads collect hardware identifiers in constructors or static initializers before app code can apply opt-out settings.
   - **Wrapper Drops**: Mediation libraries fail to pass consent parameters to their underlying sub-SDKs.

3. **IoT Companion Data Leaks (USENIX Security 2023)**:
   Companion apps frequently read local device beacons (Bluetooth MAC addresses, Wi-Fi BSSID) and pass them directly to third-party tracking endpoints.

---

## Architecture

The framework runs in four stages:

```
[Package / AAR / APK]
         |
         +---> Manifest & Asset Parser  ---> AAPT2 Collision Detector
         |
         +---> Bytecode IR Builder      ---> CFG & Dominator Analysis
                                                     |
                                                     v
                                          Inter-Procedural Taint
                                                     |
                                                     v
                                         PICO Compliance Verifier
                                                     |
                                                     v
                                          Batch Report Generator
```

- **Manifest Parser**: Reads permissions, components, and security flags.
- **Resource Merger**: Simulates AAPT2 flat-merge order to flag dangerous overrides.
- **Bytecode Analyzer**: Builds instruction-level IR and basic block control flow graphs.
- **Dominance Checker**: Computes dominator trees to confirm consent checks govern network sinks.
- **Taint Engine**: Follows data from hardware/network sources to external endpoints.

---

## Installation

```bash
git clone https://github.com/Abdulrehman-droid/secchain-audit.git
cd secchain-audit
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.9 or newer.

---

## Usage

### Scan a package
```bash
secchain scan benchmarks/02_duress_resource_poison
```

### Run batch measurement
```bash
secchain measure benchmarks --html output.html --json output.json
```

### Run the demo
```bash
python demo/run_demo.py
```

### Run tests
```bash
python -m unittest tests/test_all.py
```

---

## Benchmark Corpus

The `benchmarks/` directory contains five test packages:

| Case | Structure | Target Vulnerability |
| :--- | :--- | :--- |
| `01_benign_analytics_sdk` | Gated network calls, namespaced strings | None (Clean baseline) |
| `02_duress_resource_poison` | Ad library overrides auth endpoint and TLS config | Resource collision (Duress) |
| `03_pico_toi_toc_leak` | Constructor sends IMEI before consent call | Time-of-init leak (PICO-01) |
| `04_iot_companion_leak` | Bridge reads BLE MAC and sends to ad server | Peripheral data leak |
| `05_pico_wrapper_drop` | Wrapper updates SDK A but skips SDK B | Mediation drop (PICO-02) |

---

## References

- Y. Zhang et al., *Union under Duress: Understanding Hazards of Duplicate Resource Mismediation in Android Software Supply Chain*, USENIX Security 2023.
- Y. Zhang et al., *Navigating the Privacy Compliance Maze: Understanding Risks with Privacy-Configurable Mobile SDKs*, USENIX Security 2024.
- Y. Nan et al., *Are You Spying on Me? Large-Scale Analysis on IoT Data Exposure through Companion Apps*, USENIX Security 2023.
- H. Chen et al., *WitheredLeaf: Finding Entity-Inconsistency Bugs with LLMs*, 2025.

---

## License

Apache-2.0
