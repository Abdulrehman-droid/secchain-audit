"""
Report Generator for Empirical Security Measurements.
Produces publication-grade Markdown, JSON, and interactive HTML dashboards.
"""

from pathlib import Path
import json
from .batch_runner import CorpusMeasurementResult, PackageScanResult


class ReportGenerator:
    """Formats and exports measurement results."""

    @classmethod
    def save_json(cls, result: CorpusMeasurementResult, output_path: str | Path):
        p = Path(output_path)
        p.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def generate_markdown(cls, result: CorpusMeasurementResult) -> str:
        md = []
        md.append("# SecChain-Audit Empirical Measurement Report")
        md.append("")
        md.append("## Executive Summary")
        md.append(f"- **Total Packages Scanned**: {result.total_packages}")
        md.append(f"- **Duress Collision Vulnerability Rate**: {result.duress_prevalence_rate:.1f}% ({result.duress_vulnerable_packages}/{result.total_packages})")
        md.append(f"- **PICO Compliance Violation Rate**: {result.pico_prevalence_rate:.1f}% ({result.pico_vulnerable_packages}/{result.total_packages})")
        md.append(f"- **Time-of-Init (TOI-TOC) Leaking Packages**: {result.toi_toc_leaking_packages}")
        md.append(f"- **Mediation Wrapper-Drop Packages**: {result.wrapper_drop_packages}")
        md.append(f"- **Total Sensitive Dataflow Leaks Detected**: {result.total_taint_leaks}")
        md.append(f"- **Corpus Mean Risk Score**: {result.average_risk_score:.2f} / 10.0")
        md.append("")
        md.append("## Detailed Package Findings")
        md.append("")
        md.append("| Package Name | Risk Score | Duress Hazards | PICO Violations | Taint Leaks | Key Vulnerability |")
        md.append("| :--- | :---: | :---: | :---: | :---: | :--- |")

        for p in result.package_results:
            d_count = p.duress_report.critical_hazards if p.duress_report else 0
            p_count = len(p.pico_violations)
            t_count = len(p.taint_report.flows) if p.taint_report else 0
            summary = "None (Clean)"
            if p.pico_violations:
                summary = p.pico_violations[0].rule.name
            elif d_count > 0:
                summary = "Critical Resource Collision (Duress)"
            elif t_count > 0:
                summary = f"Sensitive Taint Leak ({p.taint_report.flows[0].source.category})"

            md.append(f"| `{p.package_name}` | **{p.risk_score:.1f}** | {d_count} | {p_count} | {t_count} | {summary} |")

        md.append("")
        md.append("## Actionable Mitigations")
        md.append("1. **Resource Namespacing**: Implement `android.namespacing=true` in Gradle to isolate third-party library resources.")
        md.append("2. **Deferred Initialization**: Enforce that SDK background telemetry tasks wait for explicit user consent signals.")
        md.append("3. **Mediation Synchronization**: Audit wrapper SDKs to ensure privacy configurations strictly fan-out to all underlying providers.")

        return "\n".join(md)

    @classmethod
    def generate_html(cls, result: CorpusMeasurementResult) -> str:
        rows = []
        for p in result.package_results:
            d_count = p.duress_report.critical_hazards if p.duress_report else 0
            p_count = len(p.pico_violations)
            t_count = len(p.taint_report.flows) if p.taint_report else 0
            badge_color = "#10b981" if p.risk_score < 3.0 else ("#f59e0b" if p.risk_score < 7.0 else "#ef4444")

            vuln_desc = "Clean / Verified"
            if p.pico_violations:
                vuln_desc = f"<b>{p.pico_violations[0].rule.id}</b>: {p.pico_violations[0].rule.name}"
            elif d_count > 0:
                vuln_desc = "<b>DURESS-01</b>: Critical Resource Hijacking"
            elif t_count > 0:
                vuln_desc = f"<b>LEAK-01</b>: {p.taint_report.flows[0].source.category} Exfiltration"

            rows.append(f"""
            <tr>
              <td><code>{p.package_name}</code></td>
              <td><span style="background-color: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;">{p.risk_score:.1f}</span></td>
              <td>{d_count}</td>
              <td>{p_count}</td>
              <td>{t_count}</td>
              <td>{vuln_desc}</td>
            </tr>
            """)

        table_rows_html = "\n".join(rows)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecChain-Audit: Empirical Measurement Dashboard</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #f8fafc; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    h1 {{ color: #38bdf8; font-size: 28px; margin-bottom: 8px; }}
    .subtitle {{ color: #94a3b8; margin-bottom: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 18px; text-align: center; }}
    .card .num {{ font-size: 32px; font-weight: bold; color: #38bdf8; margin-top: 6px; }}
    .card.alert .num {{ color: #f87171; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
    code {{ color: #a5f3fc; font-family: "JetBrains Mono", monospace; }}
    .chart-box {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 24px; border: 1px solid #334155; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ SecChain-Audit: Software Supply Chain Security Dashboard</h1>
    <div class="subtitle">Empirical Measurement across Mobile & IoT SDK Ecosystem (Resource Duress & PICO Compliance)</div>

    <div class="grid">
      <div class="card">
        <div>Packages Analyzed</div>
        <div class="num">{result.total_packages}</div>
      </div>
      <div class="card alert">
        <div>Duress Vulnerability Rate</div>
        <div class="num">{result.duress_prevalence_rate:.1f}%</div>
      </div>
      <div class="card alert">
        <div>PICO Compliance Failures</div>
        <div class="num">{result.pico_prevalence_rate:.1f}%</div>
      </div>
      <div class="card">
        <div>Data Leaks Prevented</div>
        <div class="num">{result.total_taint_leaks}</div>
      </div>
    </div>

    <div class="chart-box">
      <h3 style="margin-top:0; color: #38bdf8;">Vulnerability Distribution</h3>
      <svg width="100%" height="90" viewBox="0 0 600 90">
        <rect x="0" y="20" width="180" height="40" fill="#ef4444" rx="4" />
        <text x="10" y="45" fill="white" font-size="12" font-weight="bold">Resource Duress ({result.duress_prevalence_rate:.0f}%)</text>
        <rect x="190" y="20" width="220" height="40" fill="#f59e0b" rx="4" />
        <text x="200" y="45" fill="white" font-size="12" font-weight="bold">PICO TOI-TOC Bypass ({result.pico_prevalence_rate:.0f}%)</text>
        <rect x="420" y="20" width="170" height="40" fill="#10b981" rx="4" />
        <text x="430" y="45" fill="white" font-size="12" font-weight="bold">Benign / Compliant</text>
      </svg>
    </div>

    <h3>Package Audit Breakdown</h3>
    <table>
      <thead>
        <tr>
          <th>Package Name</th>
          <th>Risk</th>
          <th>Duress Hazards</th>
          <th>PICO Violations</th>
          <th>Taint Flows</th>
          <th>Primary Finding</th>
        </tr>
      </thead>
      <tbody>
        {table_rows_html}
      </tbody>
    </table>
  </div>
</body>
</html>"""
        return html
