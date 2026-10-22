from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from security_automation.models import Component


def _iter_component_dicts(components: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for component in components:
        if not isinstance(component, dict):
            continue
        yield component
        nested = component.get("components")
        if isinstance(nested, list):
            yield from _iter_component_dicts(nested)


def load_components(path: Path) -> list[Component]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path} is not a CycloneDX SBOM")

    roots: list[Any] = []
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        roots.append(metadata["component"])
    if isinstance(document.get("components"), list):
        roots.extend(document["components"])

    components: list[Component] = []
    seen: set[str] = set()
    for raw in _iter_component_dicts(roots):
        purl = raw.get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:") or purl in seen:
            continue
        seen.add(purl)
        name = raw.get("name")
        version = raw.get("version")
        components.append(
            Component(
                name=str(name or purl),
                version=str(version or ""),
                purl=purl,
            )
        )
    return components

