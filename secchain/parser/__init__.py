"""
Parser module for manifests, resources, dependencies, and bytecode IR.
"""

from .manifest_parser import ManifestParser, ManifestComponent, AndroidManifest
from .resource_merger import ResourceMerger, ResourceItem, ResourceCollision, DuressReport
from .dependency_resolver import DependencyResolver, DependencyNode, DependencyGraph
from .bytecode_analyzer import BytecodeAnalyzer, MethodIR, Instruction, BasicBlockIR

__all__ = [
    "ManifestParser",
    "ManifestComponent",
    "AndroidManifest",
    "ResourceMerger",
    "ResourceItem",
    "ResourceCollision",
    "DuressReport",
    "DependencyResolver",
    "DependencyNode",
    "DependencyGraph",
    "BytecodeAnalyzer",
    "MethodIR",
    "Instruction",
    "BasicBlockIR",
]
