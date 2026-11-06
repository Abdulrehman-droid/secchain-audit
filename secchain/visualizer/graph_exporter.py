"""
Exports Call Graphs and Taint Flow Paths to Mermaid and DOT formats.
"""

from typing import List, Set, Dict
from ..analysis.callgraph import CallGraph
from ..analysis.taint_engine import TaintReport, TaintFlow


class GraphExporter:
    """Generates graph representations for visual analysis."""

    @classmethod
    def to_mermaid_callgraph(cls, cg: CallGraph, max_nodes: int = 25) -> str:
        lines = ["graph TD"]
        count = 0
        for caller, callees in cg.edges.items():
            c_label = caller.split(".")[-1].replace("<", "").replace(">", "")
            for callee in callees:
                ce_label = callee.split(".")[-1].replace("<", "").replace(">", "")
                lines.append(f'    {c_label}["{caller}"] --> {ce_label}["{callee}"]')
                count += 1
                if count >= max_nodes:
                    break
            if count >= max_nodes:
                break
        return "\n".join(lines)

    @classmethod
    def to_mermaid_taint_flow(cls, flow: TaintFlow) -> str:
        lines = ["graph LR"]
        src_label = f"SOURCE: {flow.source.category}\\n{flow.source.api_pattern}"
        sink_label = f"SINK: {flow.sink.category}\\n{flow.sink_method}"
        origin_label = f"Method: {flow.origin_method}"

        lines.append(f'    Src["{src_label}"]:::srcStyle --> Orig["{origin_label}"]')
        lines.append(f'    Orig --> Sink["{sink_label}"]:::sinkStyle')
        lines.append("    classDef srcStyle fill:#f87171,stroke:#b91c1c,color:#fff,font-weight:bold;")
        lines.append("    classDef sinkStyle fill:#ef4444,stroke:#991b1b,color:#fff,font-weight:bold;")
        return "\n".join(lines)
