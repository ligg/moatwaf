from __future__ import annotations

from typing import Any, Iterable, Mapping

from security_automation.models import Component, Finding, KeVEntry


def normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    if severity in {"moderate"}:
        return "medium"
    if severity in {"important"}:
        return "high"
    if severity in {"none"}:
        return "low"
    if severity in {"critical", "high", "medium", "low", "unknown"}:
        return severity
    return "unknown"


def _references(details: Mapping[str, Any]) -> tuple[str, ...]:
    references = {
        raw.get("url")
        for raw in details.get("references", [])
        if isinstance(raw, dict) and isinstance(raw.get("url"), str)
    }
    return tuple(sorted(references))


def _cwe_ids(details: Mapping[str, Any]) -> tuple[str, ...]:
    cwes: set[str] = set()
    for source in [details.get("database_specific", {})]:
        if isinstance(source, dict):
            for item in source.get("cwe_ids", []) or []:
                if isinstance(item, str):
                    cwes.add(item.upper() if item.upper().startswith("CWE-") else item)
    for affected in details.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        source = affected.get("database_specific", {})
        if not isinstance(source, dict):
            continue
        for item in source.get("cwe_ids", []) or []:
            if isinstance(item, str) and item.upper().startswith("CWE-"):
                cwes.add(item.upper())
    return tuple(sorted(cwes))


def _fixed_versions(details: Mapping[str, Any]) -> tuple[str, ...]:
    versions: set[str] = set()
    for affected in details.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        for package_range in affected.get("ranges", []) or []:
            if not isinstance(package_range, dict):
                continue
            for event in package_range.get("events", []) or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    versions.add(event["fixed"])
        for version in affected.get("versions", []) or []:
            if isinstance(version, str) and version.startswith(">"):
                versions.add(version)
    return tuple(sorted(versions))


def _severity(details: Mapping[str, Any]) -> str:
    database_specific = details.get("database_specific", {})
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return normalize_severity(database_specific["severity"])
    severity = details.get("severity", [])
    if isinstance(severity, list):
        for raw in severity:
            if not isinstance(raw, dict):
                continue
            score = raw.get("score")
            if isinstance(score, (int, float)):
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
    return "unknown"


def _cvss_score(details: Mapping[str, Any]) -> float | None:
    for raw in details.get("severity", []) or []:
        if not isinstance(raw, dict):
            continue
        score = raw.get("score")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def _summary(details: Mapping[str, Any], vuln_id: str) -> str:
    summary = details.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    return vuln_id


def build_findings(
    components: Iterable[Component],
    osv_matches: Mapping[str, Iterable[str]],
    details_by_id: Mapping[str, Mapping[str, Any]],
    kev: Mapping[str, KeVEntry],
    cwe_to_rule: Mapping[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for component in components:
        for vuln_id in sorted(set(osv_matches.get(component.purl, []))):
            key = (component.purl, vuln_id)
            if key in seen:
                continue
            seen.add(key)
            details = details_by_id.get(vuln_id, {})
            aliases = tuple(
                sorted(
                    {
                        alias
                        for alias in details.get("aliases", []) or []
                        if isinstance(alias, str)
                    }
                )
            )
            identifiers = {vuln_id, *aliases}
            kev_entry = next(
                (kev[identifier] for identifier in sorted(identifiers) if identifier in kev),
                None,
            )
            cwe_ids = _cwe_ids(details)
            rule_family = next(
                (cwe_to_rule[cwe] for cwe in cwe_ids if cwe in cwe_to_rule),
                None,
            )
            findings.append(
                Finding(
                    id=vuln_id,
                    aliases=aliases,
                    summary=_summary(details, vuln_id),
                    component=component.name,
                    version=component.version,
                    purl=component.purl,
                    severity=_severity(details),
                    cvss_score=_cvss_score(details),
                    fixed_versions=_fixed_versions(details),
                    kev=kev_entry is not None,
                    kev_due_date=kev_entry.due_date if kev_entry else None,
                    references=_references(details),
                    cwe_ids=cwe_ids,
                    rule_family=rule_family,
                )
            )
    return sorted(findings, key=lambda item: item.risk_sort_key)

