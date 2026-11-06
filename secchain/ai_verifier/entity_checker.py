"""
Entity Inconsistency Checker between declared privacy disclosures and program bytecode sinks.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from ..analysis.taint_engine import TaintReport, TaintFlow


@dataclass
class PolicyStatement:
    data_type: str         # e.g. "LOCATION", "DEVICE_ID", "ANALYTICS"
    allowed: bool          # True if stated as collected, False if stated as "not collected"
    purpose: str           # "advertising", "analytics", "functionality", "none"


@dataclass
class InconsistencyFinding:
    severity: str          # CRITICAL, HIGH, MEDIUM
    discrepancy_type: str  # UNDECLARED_COLLECTION, PURPOSE_MISMATCH
    data_category: str
    declared_policy: str
    observed_bytecode: str
    explanation: str


class EntityChecker:
    """Verifies semantic consistency between privacy statements and static dataflows."""

    @classmethod
    def audit(cls, declared_policies: List[PolicyStatement], taint_report: TaintReport) -> List[InconsistencyFinding]:
        findings: List[InconsistencyFinding] = []
        policy_map = {p.data_type.upper(): p for p in declared_policies}

        observed_categories: Dict[str, List[TaintFlow]] = {}
        for flow in taint_report.flows:
            cat = flow.source.category.upper()
            observed_categories.setdefault(cat, []).append(flow)

        for cat, flows in observed_categories.items():
            policy = policy_map.get(cat)

            if policy and not policy.allowed:
                findings.append(InconsistencyFinding(
                    severity="CRITICAL",
                    discrepancy_type="UNDECLARED_COLLECTION",
                    data_category=cat,
                    declared_policy=f"Policy states {cat} is NEVER collected or accessed.",
                    observed_bytecode=f"Found {len(flows)} dataflow(s) transmitting {cat} to external sink '{flows[0].sink_method}'.",
                    explanation=(
                        f"Direct Entity-Inconsistency: Application/SDK public disclosure claims no {cat} "
                        f"is collected, but static analysis detected active dataflow to network sink."
                    ),
                ))
            elif not policy:
                findings.append(InconsistencyFinding(
                    severity="MEDIUM",
                    discrepancy_type="UNDECLARED_COLLECTION",
                    data_category=cat,
                    declared_policy="No policy disclosure provided for this data type.",
                    observed_bytecode=f"Observed dataflow transmitting {cat} to '{flows[0].sink_method}'.",
                    explanation=f"Missing disclosure: {cat} is harvested without declared user justification.",
                ))

        return findings

    @classmethod
    def generate_llm_prompt(cls, declared_text: str, taint_report: TaintReport) -> str:
        flows_summary = "\n".join(
            f"- Source: {f.source.category} ({f.source.api_pattern}) -> Sink: {f.sink.category} ({f.sink_method})"
            for f in taint_report.flows
        )
        return (
            "You are a System Security and Privacy Auditor specializing in Entity-Inconsistency detection.\n"
            "Compare the developer's declared Privacy Policy statement against the verified bytecode dataflows:\n\n"
            f"=== DECLARED PRIVACY POLICY ===\n{declared_text}\n\n"
            f"=== VERIFIED STATIC BYTECODE FLOWS ===\n{flows_summary}\n\n"
            "Analyze whether any observed bytecode flow violates the stated disclosures. "
            "Identify omissions, misleading purpose justifications, and compliance discrepancies."
        )
