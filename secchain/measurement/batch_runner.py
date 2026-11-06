"""
Batch Runner for Empirical Supply-Chain Measurements.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import json

from ..parser.manifest_parser import ManifestParser, AndroidManifest
from ..parser.resource_merger import ResourceMerger, DuressReport
from ..parser.bytecode_analyzer import BytecodeAnalyzer, ClassIR
from ..parser.dependency_resolver import DependencyResolver, DependencyGraph
from ..analysis.callgraph import CallGraphBuilder
from ..analysis.taint_engine import TaintEngine, TaintReport
from ..analysis.pico_verifier import PICOVerifier, PICOViolation
from ..ai_verifier.entity_checker import EntityChecker, InconsistencyFinding


@dataclass
class PackageScanResult:
    package_name: str
    manifest: Optional[AndroidManifest] = None
    duress_report: Optional[DuressReport] = None
    taint_report: Optional[TaintReport] = None
    pico_violations: List[PICOViolation] = field(default_factory=list)
    ai_inconsistencies: List[InconsistencyFinding] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "risk_score": round(self.risk_score, 2),
            "duress": self.duress_report.to_dict() if self.duress_report else None,
            "taint": self.taint_report.to_dict() if self.taint_report else None,
            "pico_violations_count": len(self.pico_violations),
            "pico_violations": [
                {
                    "rule_id": v.rule.id,
                    "rule_name": v.rule.name,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                }
                for v in self.pico_violations
            ],
            "ai_inconsistencies_count": len(self.ai_inconsistencies),
        }


@dataclass
class CorpusMeasurementResult:
    total_packages: int = 0
    duress_vulnerable_packages: int = 0
    pico_vulnerable_packages: int = 0
    toi_toc_leaking_packages: int = 0
    wrapper_drop_packages: int = 0
    total_collisions: int = 0
    total_taint_leaks: int = 0
    average_risk_score: float = 0.0
    package_results: List[PackageScanResult] = field(default_factory=list)

    @property
    def duress_prevalence_rate(self) -> float:
        return (self.duress_vulnerable_packages / self.total_packages * 100) if self.total_packages else 0.0

    @property
    def pico_prevalence_rate(self) -> float:
        return (self.pico_vulnerable_packages / self.total_packages * 100) if self.total_packages else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packages": self.total_packages,
            "duress_vulnerable_packages": self.duress_vulnerable_packages,
            "duress_prevalence_rate": round(self.duress_prevalence_rate, 2),
            "pico_vulnerable_packages": self.pico_vulnerable_packages,
            "pico_prevalence_rate": round(self.pico_prevalence_rate, 2),
            "toi_toc_leaking_packages": self.toi_toc_leaking_packages,
            "wrapper_drop_packages": self.wrapper_drop_packages,
            "total_collisions": self.total_collisions,
            "total_taint_leaks": self.total_taint_leaks,
            "average_risk_score": round(self.average_risk_score, 2),
            "packages": [p.to_dict() for p in self.package_results],
        }


class BatchRunner:
    """Executes end-to-end security audits across package benchmarks."""

    @classmethod
    def scan_package_dir(cls, pkg_dir: str | Path) -> PackageScanResult:
        p = Path(pkg_dir)
        manifest_file = p / "AndroidManifest.xml"
        manifest_json = p / "manifest.json"
        res_dir = p / "res"
        res_json = p / "resources.json"
        code_file = p / "code.py"
        bytecode_json = p / "bytecode.json"
        deps_json = p / "dependencies.json"

        pkg_name = p.name

        # 1. Parse Manifest
        manifest = None
        if manifest_json.exists():
            manifest = ManifestParser.parse_file(manifest_json)
            pkg_name = manifest.package_name
        elif manifest_file.exists():
            manifest = ManifestParser.parse_file(manifest_file)
            pkg_name = manifest.package_name

        # 2. Parse Resources and Duress Collision
        duress_report = None
        merger = ResourceMerger(app_package=pkg_name)
        if res_json.exists():
            data = json.loads(res_json.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and "packages" in data:
                order = data.get("precedence_order", list(data["packages"].keys()))
                merger.precedence_order = order
                for p_name in order:
                    if p_name in data["packages"]:
                        merger.load_resources_from_dict(p_name, data["packages"][p_name])
            else:
                merger.load_resources_from_dict(pkg_name, data)
            duress_report = merger.merge_and_audit()
        elif res_dir.exists():
            merger.load_resources_from_directory(pkg_name, res_dir)
            duress_report = merger.merge_and_audit()

        # 3. Parse Bytecode and Build IR
        classes: Dict[str, ClassIR] = {}
        if bytecode_json.exists():
            classes = BytecodeAnalyzer.from_json(bytecode_json.read_text(encoding="utf-8-sig"))
        elif code_file.exists():
            code_text = code_file.read_text(encoding="utf-8-sig")
            c_ir = BytecodeAnalyzer.from_python_code(code_text, class_name=pkg_name, package=pkg_name)
            classes[pkg_name] = c_ir

        # 4. Call Graph & Taint Engine
        callgraph = CallGraphBuilder.build(classes)
        taint_engine = TaintEngine()
        taint_report = taint_engine.analyze(classes, callgraph)

        # 5. Dependency Graph & PICO Verification
        is_wrapper = False
        child_sdks = []
        if deps_json.exists():
            dep_graph = DependencyResolver.from_file(deps_json)
            wrappers = dep_graph.find_wrappers()
            if wrappers:
                is_wrapper = True
                child_sdks = wrappers[0].dependencies
            elif dep_graph.root_package in dep_graph.nodes:
                root_node = dep_graph.nodes[dep_graph.root_package]
                if root_node.category == "mediation_wrapper" or len(root_node.dependencies) >= 2:
                    is_wrapper = True
                    child_sdks = root_node.dependencies

        pico_violations = PICOVerifier.verify(
            classes,
            taint_report,
            callgraph,
            is_wrapper=is_wrapper,
            child_sdks=child_sdks,
        )

        d_risk = duress_report.risk_score if duress_report else 0.0
        t_risk = min(10.0, len(taint_report.flows) * 2.5)
        p_risk = min(10.0, len(pico_violations) * 3.0)
        overall_risk = min(10.0, max(d_risk, (t_risk + p_risk + d_risk) / 3.0))

        return PackageScanResult(
            package_name=pkg_name,
            manifest=manifest,
            duress_report=duress_report,
            taint_report=taint_report,
            pico_violations=pico_violations,
            risk_score=overall_risk,
        )

    @classmethod
    def scan_corpus(cls, corpus_dir: str | Path) -> CorpusMeasurementResult:
        corpus_path = Path(corpus_dir)
        results: List[PackageScanResult] = []

        subdirs = sorted([d for d in corpus_path.iterdir() if d.is_dir() and not d.name.startswith(".")])
        for d in subdirs:
            res = cls.scan_package_dir(d)
            results.append(res)

        total_pkgs = len(results)
        duress_vulnerable = sum(1 for r in results if r.duress_report and (r.duress_report.critical_hazards > 0 or r.duress_report.high_hazards > 0))
        pico_vulnerable = sum(1 for r in results if r.pico_violations)
        toi_toc_count = sum(1 for r in results if any(v.rule.id == "PICO-01" for v in r.pico_violations))
        wrapper_drop_count = sum(1 for r in results if any(v.rule.id == "PICO-02" for v in r.pico_violations))
        total_collisions = sum(r.duress_report.total_collisions for r in results if r.duress_report)
        total_leaks = sum(len(r.taint_report.flows) for r in results if r.taint_report)
        avg_risk = sum(r.risk_score for r in results) / total_pkgs if total_pkgs else 0.0

        return CorpusMeasurementResult(
            total_packages=total_pkgs,
            duress_vulnerable_packages=duress_vulnerable,
            pico_vulnerable_packages=pico_vulnerable,
            toi_toc_leaking_packages=toi_toc_count,
            wrapper_drop_packages=wrapper_drop_count,
            total_collisions=total_collisions,
            total_taint_leaks=total_leaks,
            average_risk_score=avg_risk,
            package_results=results,
        )


