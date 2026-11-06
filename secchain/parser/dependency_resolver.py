"""
Dependency Graph & Transitive Wrapper Resolver.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from pathlib import Path
import json


@dataclass
class DependencyNode:
    package_name: str
    version: str = "1.0.0"
    is_direct: bool = False
    depth: int = 0
    category: str = "unknown"  # ads, analytics, iot, networking, utility, mediation_wrapper
    dependencies: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyGraph:
    root_package: str
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)

    def get_node(self, package_name: str) -> Optional[DependencyNode]:
        return self.nodes.get(package_name)

    def get_direct_dependencies(self) -> List[DependencyNode]:
        return [n for n in self.nodes.values() if n.is_direct]

    def get_transitive_dependencies(self) -> List[DependencyNode]:
        return [n for n in self.nodes.values() if not n.is_direct and n.package_name != self.root_package]

    def get_max_depth(self) -> int:
        return max((n.depth for n in self.nodes.values()), default=0)

    def find_wrappers(self) -> List[DependencyNode]:
        """Identifies wrapper/mediation candidates that depend on 2+ other SDKs."""
        return [
            n for n in self.nodes.values()
            if n.category == "mediation_wrapper" or len(n.dependencies) >= 2
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_package": self.root_package,
            "max_depth": self.get_max_depth(),
            "total_dependencies": len(self.nodes) - 1,
            "direct_count": len(self.get_direct_dependencies()),
            "transitive_count": len(self.get_transitive_dependencies()),
            "wrappers": [w.package_name for w in self.find_wrappers()],
            "nodes": {
                name: {
                    "version": node.version,
                    "is_direct": node.is_direct,
                    "depth": node.depth,
                    "category": node.category,
                    "dependencies": node.dependencies,
                }
                for name, node in self.nodes.items()
            },
        }


class DependencyResolver:
    """Builds and analyzes dependency graphs for mobile & IoT apps."""

    CATEGORY_KEYWORDS = {
        "ads": ["admob", "ads", "unity3d.ads", "applovin", "ironsource", "vungle", "facebook.audience"],
        "analytics": ["firebase.analytics", "adjust", "appsflyer", "amplitude", "mixpanel", "flurry"],
        "iot": ["ble", "bluetooth", "mqtt", "zigbee", "tuya", "smartlife", "tapo", "esp32"],
        "networking": ["okhttp", "retrofit", "volley", "ktor", "requests"],
    }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DependencyGraph:
        root = data.get("root_package", "app.main")
        graph = DependencyGraph(root_package=root)
        raw_nodes = data.get("nodes", {})

        for pkg, details in raw_nodes.items():
            deps = details.get("dependencies", [])
            version = details.get("version", "1.0.0")
            cat = details.get("category", cls._infer_category(pkg))
            graph.nodes[pkg] = DependencyNode(
                package_name=pkg,
                version=version,
                is_direct=(pkg in data.get("direct_dependencies", [])),
                category=cat,
                dependencies=deps,
            )

        if root not in graph.nodes:
            root_deps = data.get("direct_dependencies", list(raw_nodes.keys()))
            graph.nodes[root] = DependencyNode(
                package_name=root,
                version="1.0.0",
                is_direct=True,
                depth=0,
                category="root_application",
                dependencies=root_deps,
            )

        root_node = graph.nodes[root]
        for dep in root_node.dependencies:
            if dep in graph.nodes:
                graph.nodes[dep].is_direct = True

        cls._compute_depths(graph, root)

        for node in graph.nodes.values():
            if len(node.dependencies) >= 2:
                child_cats = [graph.nodes[d].category for d in node.dependencies if d in graph.nodes]
                if any(c in ["ads", "analytics", "iot"] for c in child_cats) or node.category == "mediation_wrapper":
                    node.category = "mediation_wrapper"

        return graph

    @classmethod
    def from_file(cls, filepath: str | Path) -> DependencyGraph:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Dependency file not found: {filepath}")
        content = path.read_text(encoding="utf-8-sig")
        data = json.loads(content)
        return cls.from_dict(data)

    @classmethod
    def _compute_depths(cls, graph: DependencyGraph, root: str):
        visited = {root: 0}
        queue = [(root, 0)]

        while queue:
            curr, depth = queue.pop(0)
            node = graph.nodes.get(curr)
            if not node:
                continue
            node.depth = depth

            for dep in node.dependencies:
                if dep not in visited or visited[dep] > depth + 1:
                    visited[dep] = depth + 1
                    queue.append((dep, depth + 1))

    @classmethod
    def _infer_category(cls, pkg: str) -> str:
        pkg_lower = pkg.lower()
        for cat, keywords in cls.CATEGORY_KEYWORDS.items():
            if any(k in pkg_lower for k in keywords):
                return cat
        return "utility"
