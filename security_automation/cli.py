from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from security_automation.feeds import (
    fetch_kev,
    fetch_nvd_cve,
    fetch_osv_vulnerabilities,
    query_osv,
)
from security_automation.matcher import build_findings, normalize_severity
from security_automation.models import Component, KeVEntry
from security_automation.report import render_issue, render_report
from security_automation.sbom import load_components


DEFAULT_CWE_TO_RULE = {
    "CWE-20": "PROTO",
    "CWE-22": "PATH",
    "CWE-77": "CMDI",
    "CWE-78": "CMDI",
    "CWE-79": "XSS",
    "CWE-89": "SQLI",
    "CWE-94": "PROTO",
    "CWE-502": "PROTO",
    "CWE-611": "PROTO",
    "CWE-918": "SSRF",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(findings),
        "kev": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        summary[severity] += 1
        if finding.get("kev"):
            summary["kev"] += 1
    return summary


def build_scan(
    *,
    components: list[Component],
    kev: Mapping[str, KeVEntry],
    osv_matches: Mapping[str, list[str]],
    details_by_id: Mapping[str, Mapping[str, Any]],
    generated_at: str | None = None,
    errors: list[str] | None = None,
    cwe_to_rule: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    findings = build_findings(
        components,
        osv_matches,
        details_by_id,
        kev,
        cwe_to_rule or DEFAULT_CWE_TO_RULE,
    )
    finding_dicts = [finding.to_dict() for finding in findings]
    return {
        "schemaVersion": 1,
        "generatedAt": generated_at or _utc_now(),
        "components": len(components),
        "summary": _summary(finding_dicts),
        "findings": finding_dicts,
        "errors": errors or [],
    }


def _first_nvd_metric(document: Mapping[str, Any]) -> dict[str, Any]:
    metrics = document.get("metrics", {})
    if not isinstance(metrics, dict):
        return {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, [])
        if isinstance(values, list) and values and isinstance(values[0], dict):
            cvss = values[0].get("cvssData", {})
            if isinstance(cvss, dict):
                return cvss
    return {}


def enrich_scan_with_nvd(
    scan: dict[str, Any],
    nvd_documents: Mapping[str, Mapping[str, Any]],
) -> None:
    for finding in scan.get("findings", []):
        cve_ids = finding.get("cveIds", [])
        document = next(
            (nvd_documents[cve_id] for cve_id in cve_ids if cve_id in nvd_documents),
            None,
        )
        if document is None:
            continue
        cvss = _first_nvd_metric(document)
        score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity")
        if isinstance(score, (int, float)):
            finding["cvssScore"] = float(score)
            if finding.get("severity") == "unknown":
                finding["severity"] = normalize_severity(severity)
        references = set(finding.get("references", []))
        for raw in document.get("references", []) or []:
            if isinstance(raw, dict) and isinstance(raw.get("url"), str):
                references.add(raw["url"])
        finding["references"] = sorted(references)


def enrich_with_nvd(
    scan: dict[str, Any],
    *,
    api_key: str,
    max_cves: int = 50,
) -> list[str]:
    cve_ids = sorted(
        {
            cve_id
            for finding in scan.get("findings", [])
            for cve_id in finding.get("cveIds", [])
            if cve_id.startswith("CVE-")
        }
    )[:max_cves]
    documents: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for cve_id in cve_ids:
        try:
            document = fetch_nvd_cve(cve_id, api_key=api_key)
            if document:
                documents[cve_id] = document
        except Exception as exc:  # noqa: BLE001 - preserve partial enrichment
            errors.append(f"NVD {cve_id}: {exc}")
    enrich_scan_with_nvd(scan, documents)
    return errors


def write_scan_outputs(scan: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "vulnerabilities.json").write_text(
        json.dumps(scan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(render_report(scan), encoding="utf-8")
    (output_dir / "issue.md").write_text(render_issue(scan), encoding="utf-8")


def run_scan(
    *,
    sbom_path: Path,
    output_dir: Path,
    max_details: int = 250,
    nvd_api_key: str = "",
) -> dict[str, Any]:
    components = load_components(sbom_path)
    errors: list[str] = []
    try:
        kev = fetch_kev()
    except Exception as exc:  # noqa: BLE001 - availability of one feed must not stop scans
        kev = {}
        errors.append(f"CISA KEV: {exc}")
    osv_matches = query_osv(component.purl for component in components)
    vuln_ids = {vuln_id for ids in osv_matches.values() for vuln_id in ids}
    details_by_id, detail_errors = fetch_osv_vulnerabilities(
        vuln_ids,
        max_details=max_details,
    )
    errors.extend(detail_errors)
    if len(vuln_ids) > max_details:
        errors.append(
            f"OSV detail lookup capped at {max_details} of {len(vuln_ids)} findings"
        )
    scan = build_scan(
        components=components,
        kev=kev,
        osv_matches=osv_matches,
        details_by_id=details_by_id,
        errors=errors,
    )
    if nvd_api_key:
        scan["nvdEnriched"] = True
        scan["errors"].extend(enrich_with_nvd(scan, api_key=nvd_api_key))
    else:
        scan["nvdEnriched"] = False
    write_scan_outputs(scan, output_dir)
    return scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a CycloneDX SBOM")
    scan_parser.add_argument("--sbom", required=True, type=Path)
    scan_parser.add_argument("--output-dir", required=True, type=Path)
    scan_parser.add_argument("--max-details", type=int, default=250)
    scan_parser.add_argument(
        "--nvd-api-key",
        default=os.getenv("NVD_API_KEY", ""),
        help="optional NVD API key; defaults to NVD_API_KEY",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        scan = run_scan(
            sbom_path=args.sbom,
            output_dir=args.output_dir,
            max_details=args.max_details,
            nvd_api_key=args.nvd_api_key,
        )
        print(
            f"Scanned {scan['components']} components; "
            f"{scan['summary']['total']} findings; {scan['summary']['kev']} KEV."
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

