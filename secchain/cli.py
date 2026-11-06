"""
SecChain-Audit Command Line Interface.
"""

import argparse
import sys
import json
from pathlib import Path

from .measurement.batch_runner import BatchRunner
from .measurement.report_generator import ReportGenerator
from .parser.resource_merger import ResourceMerger
from .visualizer.graph_exporter import GraphExporter


def main():
    parser = argparse.ArgumentParser(
        prog="secchain",
        description="SecChain-Audit: Program Analysis & Measurement Tool for Supply Chain & PICO Compliance",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Command: scan
    scan_p = subparsers.add_parser("scan", help="Scan a single package directory")
    scan_p.add_argument("path", help="Path to package directory")

    # Command: measure
    meas_p = subparsers.add_parser("measure", help="Run batch measurement across a corpus")
    meas_p.add_argument("corpus_path", help="Path to corpus directory")
    meas_p.add_argument("--html", help="Path to save HTML report", default=None)
    meas_p.add_argument("--json", help="Path to save JSON report", default=None)

    # Command: audit-resources
    res_p = subparsers.add_parser("audit-resources", help="Audit Duress resource collisions")
    res_p.add_argument("app_path", help="Path to app resource file or directory")
    res_p.add_argument("dep_paths", nargs="*", help="Paths to library resource files")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        result = BatchRunner.scan_package_dir(args.path)
        print(f"\n=== Scan Results for: {result.package_name} ===")
        print(f"Overall Risk Score: {result.risk_score:.1f} / 10.0")

        has_duress = result.duress_report and (result.duress_report.critical_hazards > 0 or result.duress_report.high_hazards > 0)
        if has_duress:
            total_hazards = result.duress_report.critical_hazards + result.duress_report.high_hazards
            print(f"\n[!] DURESS RESOURCE HAZARD: {total_hazards} collision(s) detected!")
            for c in result.duress_report.collisions:
                if c.is_duress_hazard:
                    print(f"  - Resource: {c.resource_id} (Winning pkg: {c.winning_item.source_package}, Severity: {c.severity})")
                    print(f"    Impact: {c.description}")
                    print(f"    Remediation: {c.remediation}")

        if result.pico_violations:
            print(f"\n[!] PICO COMPLIANCE VIOLATIONS: {len(result.pico_violations)} found!")
            for v in result.pico_violations:
                print(f"  - [{v.rule.id}] {v.rule.name} in {v.vulnerable_method}")
                print(f"    Evidence: {v.evidence}")
                print(f"    Remediation: {v.remediation}")

        if result.taint_report and result.taint_report.flows:
            print(f"\n[!] SENSITIVE TAINT LEAKS: {len(result.taint_report.flows)} flow(s)")
            for f in result.taint_report.flows:
                print(f"  - {f.source.category} ({f.source.api_pattern}) -> {f.sink.category} ({f.sink_method})")

        has_issues = has_duress or bool(result.pico_violations) or bool(result.taint_report and result.taint_report.flows)
        if not has_issues:
            print("\n[+] Package is CLEAN and compliant with PICO & Supply Chain standards.")

    elif args.command == "measure":
        res = BatchRunner.scan_corpus(args.corpus_path)
        print(f"\n=== Corpus Measurement Summary ===")
        print(f"Total Packages: {res.total_packages}")
        print(f"Duress Prevalence Rate: {res.duress_prevalence_rate:.1f}%")
        print(f"PICO Violation Rate: {res.pico_prevalence_rate:.1f}%")
        print(f"TOI-TOC Leaks: {res.toi_toc_leaking_packages}")
        print(f"Wrapper-Drops: {res.wrapper_drop_packages}")

        if args.html:
            html = ReportGenerator.generate_html(res)
            Path(args.html).write_text(html, encoding="utf-8")
            print(f"Saved interactive HTML report to: {args.html}")

        if args.json:
            ReportGenerator.save_json(res, args.json)
            print(f"Saved JSON dataset to: {args.json}")


if __name__ == "__main__":
    main()
