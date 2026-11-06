"""
Manifest Parser for Mobile Applications & Third-Party Library AARs.
Extracts security configurations, permissions, components, and intent filters.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
import xml.etree.ElementTree as ET
import json
from pathlib import Path


@dataclass
class IntentFilter:
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)
    data_hosts: List[str] = field(default_factory=list)
    priority: int = 0


@dataclass
class ManifestComponent:
    comp_type: str  # activity, service, receiver, provider
    name: str
    exported: Optional[bool] = None
    permission: Optional[str] = None
    intent_filters: List[IntentFilter] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)

    @property
    def is_effectively_exported(self) -> bool:
        if self.exported is not None:
            return self.exported
        # By Android convention, if intent-filters exist and targetSdkVersion >= 31,
        # exported must be explicit. Prior to 31, intent-filter implies exported=True.
        return len(self.intent_filters) > 0


@dataclass
class AndroidManifest:
    package_name: str
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: int = 21
    target_sdk: int = 34
    permissions: Set[str] = field(default_factory=set)
    application_attributes: Dict[str, str] = field(default_factory=dict)
    network_security_config: Optional[str] = None
    uses_cleartext_traffic: Optional[bool] = None
    components: List[ManifestComponent] = field(default_factory=list)
    raw_xml: str = ""

    def get_components_by_type(self, comp_type: str) -> List[ManifestComponent]:
        return [c for c in self.components if c.comp_type.lower() == comp_type.lower()]

    def has_permission(self, perm: str) -> bool:
        return perm in self.permissions or f"android.permission.{perm}" in self.permissions


class ManifestParser:
    """Parses Android Manifest XML files and structured descriptor formats."""

    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    @classmethod
    def parse_file(cls, filepath: str | Path) -> AndroidManifest:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Manifest file not found: {filepath}")

        content = path.read_text(encoding="utf-8-sig", errors="replace")
        if path.suffix.lower() == ".json":
            return cls.parse_json(content)
        return cls.parse_xml_string(content)

    @classmethod
    def parse_xml_string(cls, xml_content: str) -> AndroidManifest:
        root = ET.fromstring(xml_content)
        package_name = root.attrib.get("package", "unknown.package")
        version_code = cls._get_android_attr(root, "versionCode")
        version_name = cls._get_android_attr(root, "versionName")

        min_sdk = 21
        target_sdk = 34
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_str = cls._get_android_attr(uses_sdk, "minSdkVersion")
            target_str = cls._get_android_attr(uses_sdk, "targetSdkVersion")
            if min_str and min_str.isdigit():
                min_sdk = int(min_str)
            if target_str and target_str.isdigit():
                target_sdk = int(target_str)

        permissions = set()
        for perm in root.findall("uses-permission"):
            name = cls._get_android_attr(perm, "name")
            if name:
                permissions.add(name)

        app_attrs: Dict[str, str] = {}
        net_sec_config = None
        cleartext = None
        components: List[ManifestComponent] = []

        app_elem = root.find("application")
        if app_elem is not None:
            for k, v in app_elem.attrib.items():
                clean_k = k.replace(cls.ANDROID_NS, "android:")
                app_attrs[clean_k] = v

            net_sec_config = cls._get_android_attr(app_elem, "networkSecurityConfig")
            cleartext_str = cls._get_android_attr(app_elem, "usesCleartextTraffic")
            if cleartext_str is not None:
                cleartext = cleartext_str.lower() == "true"

            comp_tags = {
                "activity": "activity",
                "service": "service",
                "receiver": "receiver",
                "provider": "provider",
            }

            for tag, ctype in comp_tags.items():
                for elem in app_elem.findall(tag):
                    comp = cls._parse_component(elem, ctype)
                    components.append(comp)

        return AndroidManifest(
            package_name=package_name,
            version_code=version_code,
            version_name=version_name,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            permissions=permissions,
            application_attributes=app_attrs,
            network_security_config=net_sec_config,
            uses_cleartext_traffic=cleartext,
            components=components,
            raw_xml=xml_content,
        )

    @classmethod
    def parse_json(cls, json_content: str) -> AndroidManifest:
        data = json.loads(json_content)
        comps = []
        for c in data.get("components", []):
            filters = [
                IntentFilter(
                    actions=f.get("actions", []),
                    categories=f.get("categories", []),
                    data_schemes=f.get("data_schemes", []),
                    data_hosts=f.get("data_hosts", []),
                    priority=f.get("priority", 0),
                )
                for f in c.get("intent_filters", [])
            ]
            comps.append(
                ManifestComponent(
                    comp_type=c.get("comp_type", "activity"),
                    name=c.get("name", ""),
                    exported=c.get("exported"),
                    permission=c.get("permission"),
                    intent_filters=filters,
                    attributes=c.get("attributes", {}),
                )
            )

        return AndroidManifest(
            package_name=data.get("package_name", "unknown.package"),
            version_code=data.get("version_code"),
            version_name=data.get("version_name"),
            min_sdk=data.get("min_sdk", 21),
            target_sdk=data.get("target_sdk", 34),
            permissions=set(data.get("permissions", [])),
            application_attributes=data.get("application_attributes", {}),
            network_security_config=data.get("network_security_config"),
            uses_cleartext_traffic=data.get("uses_cleartext_traffic"),
            components=comps,
        )

    @classmethod
    def _parse_component(cls, elem: ET.Element, comp_type: str) -> ManifestComponent:
        name = cls._get_android_attr(elem, "name") or "unnamed"
        exported_str = cls._get_android_attr(elem, "exported")
        exported = exported_str.lower() == "true" if exported_str is not None else None
        permission = cls._get_android_attr(elem, "permission")

        attributes: Dict[str, str] = {}
        for k, v in elem.attrib.items():
            clean_k = k.replace(cls.ANDROID_NS, "android:")
            attributes[clean_k] = v

        intent_filters = []
        for if_elem in elem.findall("intent-filter"):
            actions = [cls._get_android_attr(a, "name") for a in if_elem.findall("action") if cls._get_android_attr(a, "name")]
            categories = [cls._get_android_attr(c, "name") for c in if_elem.findall("category") if cls._get_android_attr(c, "name")]
            data_schemes = [cls._get_android_attr(d, "scheme") for d in if_elem.findall("data") if cls._get_android_attr(d, "scheme")]
            data_hosts = [cls._get_android_attr(d, "host") for d in if_elem.findall("data") if cls._get_android_attr(d, "host")]
            p_str = cls._get_android_attr(if_elem, "priority")
            priority = int(p_str) if p_str and p_str.isdigit() else 0

            intent_filters.append(IntentFilter(
                actions=actions,
                categories=categories,
                data_schemes=data_schemes,
                data_hosts=data_hosts,
                priority=priority,
            ))

        return ManifestComponent(
            comp_type=comp_type,
            name=name,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            attributes=attributes,
        )

    @classmethod
    def _get_android_attr(cls, elem: ET.Element, attr_name: str) -> Optional[str]:
        # Try with Android namespace
        val = elem.attrib.get(f"{cls.ANDROID_NS}{attr_name}")
        if val is not None:
            return val
        # Try without namespace
        val = elem.attrib.get(f"android:{attr_name}")
        if val is not None:
            return val
        return elem.attrib.get(attr_name)

