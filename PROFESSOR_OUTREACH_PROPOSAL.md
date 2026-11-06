# Research Outreach Dossier: Dr. Yifan Zhang

**Faculty**: Dr. Yifan Zhang  
**Department**: Cybersecurity Center & Department of Computer Science, San Diego State University (SDSU)  
**Lab Focus**: System security and privacy, binary analysis, software supply chains, mobile and IoT security.  

---

## Email Draft

**Subject**: SecChain-Audit prototype: automated detection of Duress collisions and PICO compliance bypasses

Dear Professor Zhang,

I have been reading your group's papers on mobile supply chain security, specifically your work on duplicate resource mismediation (Duress, USENIX Security 2023) and privacy configuration bypasses in third-party SDKs (PICO, USENIX Security 2024).

To explore these ideas in practice, I built a static analysis and measurement tool called SecChain-Audit. The project automates detection for both vulnerability patterns:

1. **Resource Collision Detection (Duress)**: Simulates AAPT2 flat-merge order across multi-tier dependencies to catch cases where a third-party library overrides backend URLs, OAuth endpoints, or `@xml/network_security_config` trust anchors.
2. **PICO Verification**: Uses basic block control flow graphs and dominator trees to identify two common implementation bugs:
   - Time-of-init (TOI-TOC) leaks: Background telemetry tasks that collect device IDs during `<clinit>` or `<init>` before app code can call privacy opt-out methods.
   - Mediation wrapper drops: Aggregator libraries that receive user consent toggles but fail to forward them to sub-SDKs.
3. **IoT Companion App Taint Tracking**: Follows BLE advertisement data and Wi-Fi network information from local device managers into third-party tracking sinks.

The prototype includes a benchmark suite with five ground-truth cases, an 11-test automated suite, and an interactive HTML report generator. Across the test corpus, analysis takes under 40 milliseconds per package.

I am preparing applications for graduate research positions [PhD / MS Thesis] at SDSU and would welcome the opportunity to work in your lab. I am particularly interested in extending this work in three directions:

- Detecting evasive telemetry where SDKs hide initialization leaks behind reflection, dynamic class loading, or native JNI stubs.
- Auditing asset and resource collision behaviors in cross-platform frameworks (React Native, Flutter, and Kotlin Multiplatform).
- Applying semantic checking (building on your WitheredLeaf work) to verify whether mediation wrappers honor declared privacy specifications across multi-tier supply chains.

I have attached my resume and a technical write-up describing the SecChain-Audit architecture. The code repository is available on GitHub: https://github.com/Abdulrehman-droid/secchain-audit

Would you have 15 minutes for a brief call next week to discuss current openings in your lab?

Sincerely,

Abdul Rehman  
Email: abdulrehmanshahzad964@gmail.com  
GitHub: https://github.com/Abdulrehman-droid  

---

## Technical Mapping to Lab Publications

| Paper | Concept Applied | Implemented Module |
| :--- | :--- | :--- |
| **USENIX Security 2023** (*Union under Duress*) | AAPT2 build-time resource merge simulation, precedence conflict detection | `secchain.parser.resource_merger` |
| **USENIX Security 2024** (*PICO Compliance Maze*) | Time-of-init (TOI-TOC) static detection, wrapper consent drop analysis | `secchain.analysis.pico_verifier` |
| **USENIX Security 2023** (*IoT Companion Data Exposure*) | Taint tracking of BLE peripheral MAC addresses and local Wi-Fi identifiers | `secchain.analysis.taint_engine` |
| **Preprint 2025** (*WitheredLeaf*) | Cross-checking declared privacy disclosures against verified bytecode sinks | `secchain.ai_verifier.entity_checker` |
