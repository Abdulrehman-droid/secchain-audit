"""
Resource Merger & Duress Mismediation Detector.
Simulates build-system resource merging (AAPT2 / ARC) across multi-tier dependencies
and identifies Duplicate Resource Mismediation vulnerabilities (Duress, USENIX Security '23).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from pathlib import Path
import xml.etree.ElementTree as ET
import re
import json


@dataclass
class ResourceItem:
    res_type: str        # string, bool, integer, color, xml, layout, drawable, raw
    name: str            # resource identifier name (e.g. 'auth_endpoint', 'network_security_config')
    value: Any           # string value, parsed dict, or XML content
    source_package: str  # package or library name where it originated
    file_path: str       # relative or absolute file path
    is_security_sensitive: bool = False
    sensitivity_reason: str = ""

    @property
    def qualified_id(self) -> str:
        return f"@{self.res_type}/{self.name}"


@dataclass
class ResourceCollision:
    resource_id: str
    res_type: str
    name: str
    winning_item: ResourceItem
    overridden_items: List[ResourceItem]
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    is_duress_hazard: bool
    description: str
    remediation: str


@dataclass
class DuressReport:
    app_package: str
    total_resources: int
    total_collisions: int
    critical_hazards: int
    high_hazards: int
    collisions: List[ResourceCollision] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 to 10.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_package": self.app_package,
            "total_resources": self.total_resources,
            "total_collisions": self.total_collisions,
            "critical_hazards": self.critical_hazards,
            "high_hazards": self.high_hazards,
            "risk_score": round(self.risk_score, 2),
            "collisions": [
                {
                    "resource_id": c.resource_id,
                    "res_type": c.res_type,
                    "name": c.name,
                    "severity": c.severity,
                    "is_duress_hazard": c.is_duress_hazard,
                    "winning_package": c.winning_item.source_package,
                    "winning_value": str(c.winning_item.value)[:100],
                    "overridden_packages": [o.source_package for o in c.overridden_items],
                    "description": c.description,
                    "remediation": c.remediation,
                }
                for c in self.collisions
            ],
        }


class ResourceMerger:
    """
    Simulates Android build-time resource mediation and flags Duress vulnerabilities.
    """

    SENSITIVE_KEYWORDS = {
        "auth": "Authentication / OAuth endpoint or credential",
        "oauth": "OAuth configuration / client credentials",
        "token": "Security authentication token",
        "api_key": "API Secret Key",
        "secret": "Confidential credential",
        "endpoint": "Backend API destination URI",
        "server_url": "Remote server connection string",
        "network_security_config": "Network security configuration (TLS/Cert pinning)",
        "cert": "Certificate or Trust-Anchor specification",
        "pinning": "Public key pinning configuration",
        "ad_unit": "Monetization ad placement ID",
        "tracking_id": "Analytics tracking property",
        "mqtt_broker": "IoT message broker endpoint",
        "ble_key": "Bluetooth Low Energy authentication key",
    }

    def __init__(self, app_package: str = "app.main"):
        self.app_package = app_package
        # Storage: package_name -> list of ResourceItems
        self.package_resources: Dict[str, List[ResourceItem]] = {}
        # Order of precedence: [app, direct_dep_1, direct_dep_2, transitive_dep_1, ...]
        self.precedence_order: List[str] = [app_package]

    def add_package_resources(self, package_name: str, resources: List[ResourceItem], priority: int = 100):
        self.package_resources[package_name] = resources
        if package_name not in self.precedence_order:
            self.precedence_order.append(package_name)

    def load_resources_from_dict(self, package_name: str, data: Dict[str, Any]):
        """Loads resource definitions from structured dictionary or JSON representation."""
        items: List[ResourceItem] = []
        for res_type, entries in data.items():
            if isinstance(entries, dict):
                for name, val in entries.items():
                    item = self._create_resource_item(res_type, name, val, package_name, f"res/{res_type}/{name}")
                    items.append(item)
            elif isinstance(entries, list):
                for entry in entries:
                    name = entry.get("name", "unnamed")
                    val = entry.get("value", "")
                    path = entry.get("file_path", f"res/{res_type}/{name}")
                    item = self._create_resource_item(res_type, name, val, package_name, path)
                    items.append(item)
        self.add_package_resources(package_name, items)

    def load_resources_from_directory(self, package_name: str, res_dir: str | Path):
        """Scans a standard Android res/ directory for strings.xml, colors.xml, and xml/ configs."""
        res_path = Path(res_dir)
        if not res_path.exists():
            return

        items: List[ResourceItem] = []
        for xml_file in res_path.glob("**/*.xml"):
            rel_path = str(xml_file.relative_to(res_path))
            parent_name = xml_file.parent.name.lower()
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                if root.tag == "resources":
                    for child in root:
                        tag = child.tag
                        name = child.attrib.get("name")
                        val = child.text or ""
                        if name:
                            items.append(self._create_resource_item(tag, name, val, package_name, rel_path))
                elif parent_name == "xml":
                    name = xml_file.stem
                    raw_content = xml_file.read_text(encoding="utf-8-sig", errors="replace")
                    items.append(self._create_resource_item("xml", name, raw_content, package_name, rel_path))
            except Exception:
                continue

        self.add_package_resources(package_name, items)

    def _create_resource_item(self, res_type: str, name: str, val: Any, package: str, path: str) -> ResourceItem:
        is_sensitive = False
        reason = ""
        name_lower = name.lower()

        for kw, desc in self.SENSITIVE_KEYWORDS.items():
            if kw in name_lower:
                is_sensitive = True
                reason = desc
                break

        # Check for network security configs
        if res_type == "xml" and ("network_security" in name_lower or "net_sec" in name_lower):
            is_sensitive = True
            reason = "Network Security Config controlling cleartext traffic and TLS trust anchors"

        # Check values that resemble URLs or API endpoints
        if isinstance(val, str) and ("http://" in val or "https://" in val):
            if not is_sensitive:
                is_sensitive = True
                reason = "Configured Remote Network URL Endpoint"

        return ResourceItem(
            res_type=res_type,
            name=name,
            value=val,
            source_package=package,
            file_path=path,
            is_security_sensitive=is_sensitive,
            sensitivity_reason=reason,
        )

    def merge_and_audit(self, strategy: str = "aapt2_standard") -> DuressReport:
        """
        Simulates resource compilation and detects Duress hazards.
        Under AAPT2 standard:
        1. App resources always override library resources.
        2. Between libraries, precedence is governed by dependency graph order.
        If a lower-priority or malicious library collides with a security-critical resource,
        or if values diverge significantly, a Duress hazard is reported.
        """
        all_by_id: Dict[str, List[ResourceItem]] = {}
        total_res = 0

        # Group resources by qualified identifier (e.g. @string/auth_url)
        for pkg in self.precedence_order:
            items = self.package_resources.get(pkg, [])
            total_res += len(items)
            for item in items:
                all_by_id.setdefault(item.qualified_id, []).append(item)

        collisions: List[ResourceCollision] = []
        critical_count = 0
        high_count = 0

        for qid, items in all_by_id.items():
            if len(items) <= 1:
                continue

            # Collision occurred! Determine winner according to precedence order
            winner = items[0]
            losers = items[1:]

            # Analyze if any item in the collision is security sensitive
            is_sensitive = any(it.is_security_sensitive for it in items)
            value_diff = any(str(it.value).strip() != str(winner.value).strip() for it in losers)

            severity = "LOW"
            is_duress = False
            desc = ""
            remed = ""

            if is_sensitive and value_diff:
                # High or Critical severity
                # If the winner is an untrusted third-party library overriding app or another trusted library
                is_winner_app = (winner.source_package == self.app_package)
                sensitivity_reason = next((it.sensitivity_reason for it in items if it.is_security_sensitive), "Security Configuration")

                if not is_winner_app:
                    severity = "CRITICAL"
                    is_duress = True
                    desc = (
                        f"CRITICAL DURESS HAZARD: Third-party dependency '{winner.source_package}' silently overrides "
                        f"sensitive resource '{qid}' ({sensitivity_reason}) from '{', '.join(l.source_package for l in losers)}'. "
                        f"Overridden value: '{losers[0].value}', Winning value: '{winner.value}'."
                    )
                    remed = (
                        f"1. Enforce compile-time resource namespacing (android.namespacing=true).\n"
                        f"2. Rename colliding resource in '{winner.source_package}' using prefix '{winner.source_package.split('.')[-1]}_'.\n"
                        f"3. Explicitly define '{qid}' in the main application project to maintain developer control."
                    )
                    critical_count += 1
                else:
                    severity = "HIGH"
                    is_duress = True
                    desc = (
                        f"HIGH SEVERITY MISMEDIATION: Main application overrides sensitive resource '{qid}' "
                        f"expected by library '{', '.join(l.source_package for l in losers)}'. This may induce unintended side-effects "
                        f"or telemetry hijacking in downstream SDK components."
                    )
                    remed = f"Verify that the main app override for '{qid}' is intentional and does not break library security invariants."
                    high_count += 1
            elif value_diff:
                severity = "MEDIUM"
                desc = (
                    f"Resource collision on '{qid}': Winning package '{winner.source_package}' replaces value "
                    f"from '{', '.join(l.source_package for l in losers)}'. Values diverge."
                )
                remed = f"Namespace resource '{qid}' to prevent unintentional UI or functional glitches."
            else:
                severity = "LOW"
                desc = f"Benign duplicate resource on '{qid}': Values are identical across packages."
                remed = "No immediate security action required; clean up redundant resource definitions."

            collisions.append(ResourceCollision(
                resource_id=qid,
                res_type=winner.res_type,
                name=winner.name,
                winning_item=winner,
                overridden_items=losers,
                severity=severity,
                is_duress_hazard=is_duress,
                description=desc,
                remediation=remed,
            ))

        # Compute risk score (0 to 10)
        risk_score = min(10.0, (critical_count * 3.5) + (high_count * 1.5) + (len(collisions) * 0.1))

        return DuressReport(
            app_package=self.app_package,
            total_resources=total_res,
            total_collisions=len(collisions),
            critical_hazards=critical_count,
            high_hazards=high_count,
            collisions=collisions,
            risk_score=risk_score,
        )

