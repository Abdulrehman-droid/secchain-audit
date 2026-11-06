"""
AI & Semantic Policy Inconsistency Verifier.
Inspired by WitheredLeaf (Finding Entity-Inconsistency Bugs with LLMs).
"""

from .entity_checker import EntityChecker, PolicyStatement, InconsistencyFinding

__all__ = ["EntityChecker", "PolicyStatement", "InconsistencyFinding"]
