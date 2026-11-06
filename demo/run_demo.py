"""
SecChain-Audit: Live Demonstration Script.
Executes end-to-end security audits across mobile & IoT benchmarks
and outputs a visual HTML measurement report.
"""

import sys
import io
from pathlib import Path

# Fix Windows console UTF-8 output
if sys.platform.startswith("win"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from secchain.measurement.batch_runner import BatchRunner
from secchain.measurement.report_generator import ReportGenerator
from secchain.visualizer.graph_exporter import GraphExporter


def run():
    print("=" * 75)
    print("  [SEC] SecChain-Audit: Automated Supply Chain & Privacy Compliance Engine")
    print("=" * 75)
    print("Targeting:")
    print("  * Software Supply Chain Security: Duplicate Resource Mismediation (Duress)")
    print("  * Privacy-Configurable SDK Compliance: Time-of-Init (TOI-TOC) Leaks & Wrapper Drops")
    print("  * Mobile & IoT Systems Security: Cross-Tier Telemetry Exfiltration")
    print("=" * 75)
    print()

    benchmarks_dir = ROOT_DIR / "benchmarks"
    demo_out_dir = ROOT_DIR / "demo"
    demo_out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning benchmark corpus at: {benchmarks_dir} ...\n")
    corpus_res = BatchRunner.scan_corpus(benchmarks_dir)

    for pkg_res in corpus_res.package_results:
        print(f"---------------------------------------------------------------------------")
        print(f"[*] PACKAGE: {pkg_res.package_name}")
        print(f"   Risk Score: {pkg_res.risk_score:.1f} / 10.0")

        # Duress
        if pkg_res.duress_report and (pkg_res.duress_report.critical_hazards > 0 or pkg_res.duress_report.high_hazards > 0):
            print(f"   [!] DURESS RESOURCE HAZARD:")
            for c in pkg_res.duress_report.collisions:
                if c.is_duress_hazard:
                    print(f"      - Colliding Resource: {c.resource_id}")
                    print(f"        Winning Package:    {c.winning_item.source_package}")
                    print(f"        Severity:           {c.severity}")
                    print(f"        Vulnerability:      {c.description}")

        # PICO
        if pkg_res.pico_violations:
            print(f"   [!] PICO COMPLIANCE VIOLATION:")
            for v in pkg_res.pico_violations:
                print(f"      - [{v.rule.id}] {v.rule.name} in {v.vulnerable_method}")
                print(f"        Evidence: {v.evidence}")

        # Taint
        if pkg_res.taint_report and pkg_res.taint_report.flows:
            print(f"   [!] SENSITIVE TAINT LEAKS:")
            for f in pkg_res.taint_report.flows:
                print(f"      - Flow: {f.source.category} ({f.source.api_pattern}) -> {f.sink.category} ({f.sink_method})")
                print(f"        Mermaid Visualization snippet:")
                flow_mermaid = GraphExporter.to_mermaid_taint_flow(f)
                print("        " + flow_mermaid.replace("\n", "\n        "))

        if not pkg_res.pico_violations and (not pkg_res.duress_report or (pkg_res.duress_report.critical_hazards == 0 and pkg_res.duress_report.high_hazards == 0)) and (not pkg_res.taint_report or len(pkg_res.taint_report.flows) == 0):
            print(f"   [+] STATUS: Verified Clean & PICO-Compliant")

    print()
    print("=" * 75)
    print("EMPIRICAL CORPUS MEASUREMENT SUMMARY")
    print("=" * 75)
    print(f"Total Packages Analyzed:         {corpus_res.total_packages}")
    print(f"Duress Vulnerability Rate:       {corpus_res.duress_prevalence_rate:.1f}% ({corpus_res.duress_vulnerable_packages}/{corpus_res.total_packages})")
    print(f"PICO Non-Compliance Rate:        {corpus_res.pico_prevalence_rate:.1f}% ({corpus_res.pico_vulnerable_packages}/{corpus_res.total_packages})")
    print(f"Time-of-Init (TOI-TOC) Leaks:    {corpus_res.toi_toc_leaking_packages}")
    print(f"Mediation Wrapper Consent Drops: {corpus_res.wrapper_drop_packages}")
    print(f"Total Sensitive Flows Stopped:   {corpus_res.total_taint_leaks}")
    print(f"Corpus Average Risk Score:       {corpus_res.average_risk_score:.2f} / 10.0")

    # Generate Reports
    html_path = demo_out_dir / "demo_report.html"
    json_path = demo_out_dir / "demo_report.json"
    md_path = demo_out_dir / "demo_report.md"

    html_content = ReportGenerator.generate_html(corpus_res)
    html_path.write_text(html_content, encoding="utf-8")

    ReportGenerator.save_json(corpus_res, json_path)

    md_content = ReportGenerator.generate_markdown(corpus_res)
    md_path.write_text(md_content, encoding="utf-8")

    print()
    print(f"[+] Saved Interactive HTML Dashboard to: {html_path}")
    print(f"[+] Saved JSON Dataset to:               {json_path}")
    print(f"[+] Saved Markdown Summary to:           {md_path}")
    print("=" * 75)
    print("Demo execution finished successfully!")


if __name__ == "__main__":
    run()
