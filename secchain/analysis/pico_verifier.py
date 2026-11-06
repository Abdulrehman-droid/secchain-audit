"""
Privacy-Configurable SDK (PICO) Compliance Verifier.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from ..parser.bytecode_analyzer import ClassIR, MethodIR, Instruction
from .callgraph import CallGraph
from .taint_engine import TaintReport, TaintFlow
from .cfg import CFGBuilder


@dataclass
class PICORule:
    id: str
    name: str
    description: str


@dataclass
class PICOViolation:
    rule: PICORule
    sdk_class: str
    vulnerable_method: str
    sink_method: str
    severity: str
    evidence: str
    remediation: str


class PICOVerifier:
    """Audits SDK bytecode against PICO privacy compliance rules."""

    PRIVACY_APIS = [
        "setConsent",
        "setOptOut",
        "disableTracking",
        "setSubjectToGDPR",
        "setDoNotSell",
        "updatePrivacyConsent",
        "revokeConsent",
    ]

    RULE_TOI_TOC = PICORule(
        "PICO-01",
        "Time-of-Init to Time-of-Config (TOI-TOC) Leak",
        "SDK exfiltrates sensitive device telemetry in constructor or init() before developer configuration",
    )
    RULE_WRAPPER_DROP = PICORule(
        "PICO-02",
        "Mediation Wrapper Consent Drop",
        "Wrapper SDK receives user privacy configuration but fails to propagate it to downstream sub-SDKs",
    )
    RULE_DOMINANCE_BYPASS = PICORule(
        "PICO-03",
        "Consent Dominance Bypass",
        "Network transmission sink is not strictly dominated by a consent/opt-out check branch",
    )

    @classmethod
    def verify(
        cls,
        classes: Dict[str, ClassIR],
        taint_report: TaintReport,
        callgraph: CallGraph,
        is_wrapper: bool = False,
        child_sdks: Optional[List[str]] = None,
    ) -> List[PICOViolation]:
        violations: List[PICOViolation] = []

        # Check 1: TOI-TOC Detection
        init_methods = {"<clinit>", "<init>", "__init__", "init", "start", "initialize"}
        for flow in taint_report.flows:
            origin_method_short = flow.origin_method.split(".")[-1]
            if origin_method_short in init_methods:
                violations.append(PICOViolation(
                    rule=cls.RULE_TOI_TOC,
                    sdk_class=flow.origin_method.rsplit(".", 1)[0],
                    vulnerable_method=flow.origin_method,
                    sink_method=flow.sink_method,
                    severity="CRITICAL",
                    evidence=(
                        f"SDK method '{flow.origin_method}' transmits sensitive source '{flow.source.category}' "
                        f"to sink '{flow.sink.category}' during initial startup. "
                        f"Developers cannot invoke privacy toggles before this transmission occurs."
                    ),
                    remediation=(
                        "Defer all network telemetry until after explicit configuration. "
                        "Enforce a mandatory gate: if (consentState == UNINITIALIZED) { queueEvents(); }"
                    ),
                ))

        # Check 2: Wrapper-Drop Detection
        if is_wrapper and child_sdks:
            violations.extend(cls._check_wrapper_drop(classes, child_sdks))

        # Check 3: Dominance Check
        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                if m_name in init_methods:
                    continue
                cfg = CFGBuilder.build(m_ir)
                for b_id, block in cfg.blocks.items():
                    for inst in block.instructions:
                        if inst.is_invoke() and any(k in (inst.method_signature or "") for k in ["Http", "Socket", "requests", "connect"]):
                            doms = cfg.dominators.get(b_id, set())
                            has_dominating_branch = False
                            for d_id in doms:
                                d_block = cfg.blocks.get(d_id)
                                if d_block and any(i.is_branch() for i in d_block.instructions):
                                    has_dominating_branch = True
                                    break
                            if not has_dominating_branch and len(cfg.blocks) > 1:
                                violations.append(PICOViolation(
                                    rule=cls.RULE_DOMINANCE_BYPASS,
                                    sdk_class=c_name,
                                    vulnerable_method=m_ir.full_name,
                                    sink_method=inst.method_signature or "network_sink",
                                    severity="HIGH",
                                    evidence=(
                                        f"Method '{m_ir.full_name}' executes network sink '{inst.method_signature}' "
                                        f"without an unconditional dominating privacy consent guard check."
                                    ),
                                    remediation="Wrap sink invocation in an explicit check (e.g. if (isConsentGiven())).",
                                ))

        return violations

    @classmethod
    def _check_wrapper_drop(cls, classes: Dict[str, ClassIR], child_sdks: List[str]) -> List[PICOViolation]:
        violations = []
        found_propagate: Set[str] = set()
        privacy_method_found = False

        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                if any(api.lower() in m_name.lower() for api in cls.PRIVACY_APIS):
                    privacy_method_found = True
                    for inst in m_ir.instructions:
                        if inst.is_invoke() and inst.method_signature:
                            sig_lower = inst.method_signature.lower()
                            for child in child_sdks:
                                child_lower = child.lower()
                                child_slug = child_lower.replace(".", "_")
                                child_leaf = child_lower.split(".")[-1]
                                if child_lower in sig_lower or child_slug in sig_lower or child_leaf in sig_lower:
                                    found_propagate.add(child)

        dropped_children = set(child_sdks) - found_propagate
        if privacy_method_found and dropped_children:
            sdk_label = list(classes.keys())[0] if classes else "MediationWrapper"
            for dropped in sorted(list(dropped_children)):
                violations.append(PICOViolation(
                    rule=cls.RULE_WRAPPER_DROP,
                    sdk_class=sdk_label,
                    vulnerable_method="setConsent / updatePrivacyConsent",
                    sink_method=f"{dropped}.setConsent",
                    severity="CRITICAL",
                    evidence=(
                        f"Mediation wrapper defines privacy configuration methods, but completely omits "
                        f"propagating the user's consent status to sub-SDK '{dropped}'. "
                        f"Downstream sub-SDK will operate with default unrestricted data collection."
                    ),
                    remediation=f"Forward consent parameter to '{dropped}' inside all privacy handler methods.",
                ))

        return violations
