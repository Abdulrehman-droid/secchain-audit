"""
Control Flow Graph (CFG) and Dominance Analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from ..parser.bytecode_analyzer import BasicBlockIR, MethodIR, Instruction


@dataclass
class CFG:
    method: MethodIR
    blocks: Dict[int, BasicBlockIR] = field(default_factory=dict)
    entry_block_id: int = 0
    dominators: Dict[int, Set[int]] = field(default_factory=dict)

    def dominates(self, d: int, n: int) -> bool:
        """Returns True if block d dominates block n."""
        return d in self.dominators.get(n, set())

    def strictly_dominates(self, d: int, n: int) -> bool:
        return d != n and self.dominates(d, n)


class CFGBuilder:
    """Constructs CFG and computes Dominator Trees."""

    @classmethod
    def build(cls, method: MethodIR) -> CFG:
        blocks_dict = {b.id: b for b in method.basic_blocks}
        if not blocks_dict:
            empty_blk = BasicBlockIR(id=0, instructions=method.instructions)
            blocks_dict[0] = empty_blk

        cfg = CFG(method=method, blocks=blocks_dict, entry_block_id=0)
        cfg.dominators = cls._compute_dominators(cfg)
        return cfg

    @classmethod
    def _compute_dominators(cls, cfg: CFG) -> Dict[int, Set[int]]:
        all_blocks = set(cfg.blocks.keys())
        doms: Dict[int, Set[int]] = {}

        if not all_blocks:
            return doms

        entry = cfg.entry_block_id
        doms[entry] = {entry}

        for b in all_blocks:
            if b != entry:
                doms[b] = set(all_blocks)

        changed = True
        while changed:
            changed = False
            for b in all_blocks:
                if b == entry:
                    continue
                preds = cfg.blocks[b].predecessors
                if not preds:
                    new_dom = {b}
                else:
                    new_dom = set.intersection(*(doms[p] for p in preds if p in doms)) | {b}

                if new_dom != doms[b]:
                    doms[b] = new_dom
                    changed = True

        return doms
