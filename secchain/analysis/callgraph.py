"""
Inter-procedural Call Graph & Entry-Point Discovery.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from ..parser.bytecode_analyzer import ClassIR, MethodIR, Instruction


@dataclass
class CallGraph:
    nodes: Set[str] = field(default_factory=set)
    edges: Dict[str, Set[str]] = field(default_factory=dict)
    reverse_edges: Dict[str, Set[str]] = field(default_factory=dict)
    entry_points: Set[str] = field(default_factory=set)

    def add_edge(self, caller: str, callee: str):
        self.nodes.add(caller)
        self.nodes.add(callee)
        self.edges.setdefault(caller, set()).add(callee)
        self.reverse_edges.setdefault(callee, set()).add(caller)

    def get_callees(self, caller: str) -> Set[str]:
        return self.edges.get(caller, set())

    def get_callers(self, callee: str) -> Set[str]:
        return self.reverse_edges.get(callee, set())

    def get_reachable_from(self, start_nodes: Set[str]) -> Set[str]:
        visited = set()
        queue = list(start_nodes)
        while queue:
            curr = queue.pop(0)
            if curr not in visited:
                visited.add(curr)
                queue.extend(self.edges.get(curr, set()) - visited)
        return visited


class CallGraphBuilder:
    """Constructs inter-procedural call graph from class IR representations."""

    LIFECYCLE_ENTRY_METHODS = {
        "<clinit>",
        "<init>",
        "__init__",
        "init",
        "start",
        "onCreate",
        "onStartCommand",
        "onReceive",
        "attachBaseContext",
    }

    @classmethod
    def build(cls, classes: Dict[str, ClassIR]) -> CallGraph:
        cg = CallGraph()

        all_methods: Dict[str, MethodIR] = {}
        for c_name, c_ir in classes.items():
            for m_name, m_ir in c_ir.methods.items():
                all_methods[m_ir.full_name] = m_ir
                if m_name in cls.LIFECYCLE_ENTRY_METHODS:
                    cg.entry_points.add(m_ir.full_name)

        for caller_full, m_ir in all_methods.items():
            cg.nodes.add(caller_full)
            for inst in m_ir.instructions:
                if inst.is_invoke() and inst.method_signature:
                    callee_sig = inst.method_signature
                    matched = cls._resolve_callee(callee_sig, all_methods)
                    if matched:
                        cg.add_edge(caller_full, matched)
                    else:
                        cg.add_edge(caller_full, callee_sig)

        return cg

    @classmethod
    def _resolve_callee(cls, sig: str, all_methods: Dict[str, MethodIR]) -> Optional[str]:
        if sig in all_methods:
            return sig
        for full in all_methods.keys():
            if full.endswith(sig) or sig.endswith(full.split(".")[-1]):
                return full
        return None
