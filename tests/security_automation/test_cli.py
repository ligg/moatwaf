import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from security_automation.cli import (
    build_scan,
    enrich_scan_with_nvd,
    load_cwe_rule_map,
    write_scan_outputs,
)
from security_automation.models import Component, KeVEntry


class CliTests(unittest.TestCase):
    def test_build_scan_creates_stable_summary(self):
        component = Component("django", "3.2.0", "pkg:pypi/django@3.2.0")
        scan = build_scan(
            components=[component],
            kev={
                "CVE-2026-0001": KeVEntry(
                    cve_id="CVE-2026-0001",
                    date_added="2026-10-20",
                    due_date="2026-10-23",
                )
            },
            osv_matches={component.purl: ["GHSA-test"]},
            details_by_id={
                "GHSA-test": {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-0001"],
                    "database_specific": {
                        "severity": "HIGH",
                        "cwe_ids": ["CWE-89"],
                    },
                }
            },
            generated_at="2026-10-22T00:00:00Z",
        )

        self.assertEqual(scan["summary"]["total"], 1)
        self.assertEqual(scan["summary"]["kev"], 1)
        self.assertEqual(scan["summary"]["high"], 1)
        self.assertEqual(scan["components"], 1)

    def test_enrich_scan_with_nvd_uses_cvss_v31_metrics(self):
        scan = {
            "findings": [
                {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-0001"],
                    "cveIds": ["CVE-2026-0001"],
                    "severity": "unknown",
                    "cvssScore": None,
                    "references": [],
                }
            ]
        }
        nvd_documents = {
            "CVE-2026-0001": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}],
            }
        }

        enrich_scan_with_nvd(scan, nvd_documents)

        self.assertEqual(scan["findings"][0]["severity"], "critical")
        self.assertEqual(scan["findings"][0]["cvssScore"], 9.8)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-0001", scan["findings"][0]["references"])

    def test_enrich_scan_with_nvd_raises_severity_when_nvd_is_more_severe(self):
        scan = {
            "findings": [
                {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-0001"],
                    "cveIds": ["CVE-2026-0001"],
                    "severity": "medium",
                    "cvssScore": None,
                    "references": [],
                }
            ]
        }
        nvd_documents = {
            "CVE-2026-0001": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                }
            }
        }

        enrich_scan_with_nvd(scan, nvd_documents)

        self.assertEqual(scan["findings"][0]["severity"], "critical")

    def test_write_scan_outputs_creates_json_and_markdown(self):
        scan = {
            "generatedAt": "2026-10-22T00:00:00Z",
            "components": 1,
            "summary": {
                "total": 0,
                "kev": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "unknown": 0,
            },
            "findings": [],
            "errors": [],
        }
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            write_scan_outputs(scan, output)
            self.assertTrue((output / "vulnerabilities.json").exists())
            self.assertTrue((output / "report.md").exists())
            self.assertTrue((output / "issue.md").exists())

    def test_load_cwe_rule_map_normalizes_keys(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "map.json"
            path.write_text('{"cwe-89": "SQLI"}', encoding="utf-8")

            mapping = load_cwe_rule_map(path)

        self.assertEqual(mapping, {"CWE-89": "SQLI"})


if __name__ == "__main__":
    unittest.main()

