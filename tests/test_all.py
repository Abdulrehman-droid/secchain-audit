"""
Comprehensive Unit & Integration Test Suite for SecChain-Audit.
"""

import unittest
import json
from pathlib import Path

from secchain.parser.manifest_parser import ManifestParser, AndroidManifest
from secchain.parser.resource_merger import ResourceMerger, ResourceItem
from secchain.parser.dependency_resolver import DependencyResolver
from secchain.parser.bytecode_analyzer import BytecodeAnalyzer
from secchain.analysis.cfg import CFGBuilder
from secchain.analysis.callgraph import CallGraphBuilder
from secchain.analysis.taint_engine import TaintEngine
from secchain.analysis.pico_verifier import PICOVerifier
from secchain.ai_verifier.entity_checker import EntityChecker, PolicyStatement
from secchain.measurement.batch_runner import BatchRunner
from secchain.visualizer.graph_exporter import GraphExporter


class TestManifestParser(unittest.TestCase):
    def test_parse_json_manifest(self):
        json_data = json.dumps({
            "package_name": "com.test.app",
            "min_sdk": 24,
            "target_sdk": 34,
            "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
            "network_security_config": "@xml/network_sec_config"
        })
        manifest = ManifestParser.parse_json(json_data)
        self.assertEqual(manifest.package_name, "com.test.app")
        self.assertEqual(manifest.target_sdk, 34)
        self.assertTrue(manifest.has_permission("INTERNET"))
        self.assertEqual(manifest.network_security_config, "@xml/network_sec_config")

    def test_xml_manifest_parsing(self):
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.xml.test" android:versionCode="10">
            <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
            <uses-permission android:name="android.permission.CAMERA"/>
            <application android:usesCleartextTraffic="true">
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN"/>
                        <category android:name="android.intent.category.LAUNCHER"/>
                    </intent-filter>
                </activity>
            </application>
        </manifest>"""
        manifest = ManifestParser.parse_xml_string(xml_content)
        self.assertEqual(manifest.package_name, "com.xml.test")
        self.assertEqual(manifest.min_sdk, 21)
        self.assertEqual(manifest.target_sdk, 33)
        self.assertTrue(manifest.has_permission("CAMERA"))
        self.assertTrue(manifest.uses_cleartext_traffic)
        self.assertEqual(len(manifest.components), 1)
        self.assertTrue(manifest.components[0].is_effectively_exported)


class TestResourceMerger(unittest.TestCase):
    def test_duress_collision_detection(self):
        merger = ResourceMerger(app_package="com.target.app")
        merger.precedence_order = ["com.evil.adlib", "com.target.app"]

        merger.load_resources_from_dict("com.target.app", {
            "string": {"auth_url": "https://secure.target.com/auth"},
            "xml": {"network_security_config": "<trust-anchors><certificates src=\"system\" /></trust-anchors>"}
        })

        merger.load_resources_from_dict("com.evil.adlib", {
            "string": {"auth_url": "http://attacker.com/steal"},
            "xml": {"network_security_config": "<trust-anchors><certificates src=\"user\" /></trust-anchors>"}
        })

        report = merger.merge_and_audit()
        self.assertGreater(report.total_collisions, 0)
        self.assertGreater(report.critical_hazards, 0)
        self.assertGreater(report.risk_score, 5.0)

        critical_c = [c for c in report.collisions if c.severity == "CRITICAL"]
        self.assertTrue(any(c.name == "auth_url" for c in critical_c))

    def test_benign_collision(self):
        merger = ResourceMerger(app_package="com.target.app")
        merger.load_resources_from_dict("com.target.app", {
            "string": {"app_label": "SameLabel"}
        })
        merger.load_resources_from_dict("com.lib.util", {
            "string": {"app_label": "SameLabel"}
        })
        report = merger.merge_and_audit()
        self.assertEqual(report.critical_hazards, 0)
        self.assertEqual(report.high_hazards, 0)
        self.assertEqual(report.collisions[0].severity, "LOW")


class TestBytecodeAndCFG(unittest.TestCase):
    def test_cfg_construction_and_dominance(self):
        py_code = """
def processData(consent, data):
    if consent:
        import requests
        requests.post(data)
    return True
"""
        c_ir = BytecodeAnalyzer.from_python_code(py_code, class_name="DataProcessor")
        method = c_ir.get_method("processData")
        self.assertIsNotNone(method)

        cfg = CFGBuilder.build(method)
        self.assertGreaterEqual(len(cfg.blocks), 1)
        self.assertTrue(cfg.dominates(0, 0))


class TestTaintEngine(unittest.TestCase):
    def test_taint_propagation_and_sink(self):
        py_code = """
class SpySDK:
    def __init__(self, ctx):
        import TelephonyManager
        imei = TelephonyManager.getDeviceId()
        import requests
        requests.post(imei)
"""
        c_ir = BytecodeAnalyzer.from_python_code(py_code, class_name="SpySDK")
        classes = {"SpySDK": c_ir}

        cg = CallGraphBuilder.build(classes)
        engine = TaintEngine()
        report = engine.analyze(classes, cg)

        self.assertGreater(report.total_sources_found, 0)
        self.assertGreater(report.total_sinks_found, 0)
        self.assertGreater(len(report.flows), 0)
        self.assertEqual(report.flows[0].source.category, "DEVICE_ID")
        self.assertEqual(report.flows[0].sink.category, "NETWORK_HTTP")


class TestPICOVerifier(unittest.TestCase):
    def test_toi_toc_detection(self):
        py_code = """
class EarlyLeakSDK:
    def __init__(self):
        import TelephonyManager
        android_id = TelephonyManager.getDeviceId()
        import requests
        requests.post(android_id)

    def setConsent(self, granted):
        self.consent = granted
"""
        c_ir = BytecodeAnalyzer.from_python_code(py_code, class_name="EarlyLeakSDK")
        classes = {"EarlyLeakSDK": c_ir}
        cg = CallGraphBuilder.build(classes)
        engine = TaintEngine()
        taint_report = engine.analyze(classes, cg)

        violations = PICOVerifier.verify(classes, taint_report, cg)
        toi_toc_violations = [v for v in violations if v.rule.id == "PICO-01"]
        self.assertGreater(len(toi_toc_violations), 0)

    def test_wrapper_drop_detection(self):
        py_code = """
class WrapperSDK:
    def setConsent(self, granted):
        import sub_one
        sub_one.setConsent(granted)
"""
        c_ir = BytecodeAnalyzer.from_python_code(py_code, class_name="WrapperSDK")
        classes = {"WrapperSDK": c_ir}
        cg = CallGraphBuilder.build(classes)
        taint_report = TaintEngine().analyze(classes, cg)

        # sub_two is dropped
        violations = PICOVerifier.verify(
            classes, taint_report, cg, is_wrapper=True, child_sdks=["sub_one", "sub_two"]
        )
        drop_violations = [v for v in violations if v.rule.id == "PICO-02"]
        self.assertEqual(len(drop_violations), 1)
        self.assertIn("sub_two", drop_violations[0].evidence)


class TestEntityChecker(unittest.TestCase):
    def test_inconsistency_detection(self):
        py_code = """
class UntruthfulSDK:
    def track(self):
        import LocationManager
        loc = LocationManager.getLastKnownLocation()
        import requests
        requests.post(loc)
"""
        c_ir = BytecodeAnalyzer.from_python_code(py_code, class_name="UntruthfulSDK")
        classes = {"UntruthfulSDK": c_ir}
        taint_report = TaintEngine().analyze(classes)

        policies = [PolicyStatement(data_type="LOCATION", allowed=False, purpose="none")]
        findings = EntityChecker.audit(policies, taint_report)

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].discrepancy_type, "UNDECLARED_COLLECTION")
        self.assertEqual(findings[0].severity, "CRITICAL")


class TestVisualizer(unittest.TestCase):
    def test_mermaid_export(self):
        cg = CallGraphBuilder.build({})
        cg.add_edge("com.app.MainActivity.init", "com.sdk.Tracker.start")
        mermaid = GraphExporter.to_mermaid_callgraph(cg)
        self.assertIn("graph TD", mermaid)
        self.assertIn("MainActivity", mermaid)


class TestBatchRunner(unittest.TestCase):
    def test_corpus_measurement(self):
        res = BatchRunner.scan_corpus(r"c:\Users\abc\Desktop\secchain-audit\benchmarks")
        self.assertEqual(res.total_packages, 5)
        self.assertGreater(res.duress_vulnerable_packages, 0)
        self.assertGreater(res.pico_vulnerable_packages, 0)
        self.assertGreater(res.toi_toc_leaking_packages, 0)
        self.assertGreater(res.wrapper_drop_packages, 0)


if __name__ == "__main__":
    unittest.main()
