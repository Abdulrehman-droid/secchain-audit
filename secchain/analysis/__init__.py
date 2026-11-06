"""
Program Analysis Module: CFG, Call Graph, Taint Tracking, and PICO Verifier.
"""

from .cfg import CFG, CFGBuilder
from .callgraph import CallGraph, CallGraphBuilder
from .taint_engine import TaintEngine, TaintSource, TaintSink, TaintFlow, TaintReport
from .pico_verifier import PICOVerifier, PICOViolation, PICORule

__all__ = [
    "CFG",
    "CFGBuilder",
    "CallGraph",
    "CallGraphBuilder",
    "TaintEngine",
    "TaintSource",
    "TaintSink",
    "TaintFlow",
    "TaintReport",
    "PICOVerifier",
    "PICOViolation",
    "PICORule",
]
