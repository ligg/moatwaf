import unittest

from security_automation.matcher import build_findings
from security_automation.models import Component, KeVEntry


class MatcherTests(unittest.TestCase):
    def test_build_findings_marks_kev_and_extracts_fixed_versions(self):
        component = Component("django", "3.2.0", "pkg:pypi/django@3.2.0")
        details = {
            "GHSA-test": {
                "id": "GHSA-test",
                "aliases": ["CVE-2026-0001"],
                "summary": "Example issue",
                "database_specific": {
                    "severity": "HIGH",
                    "cwe_ids": ["CWE-89"],
                },
                "affected": [
                    {
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "3.2.9"},
                                ]
                            }
                        ]
                    }
                ],
                "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
            }
        }
        kev = {
            "CVE-2026-0001": KeVEntry(
                cve_id="CVE-2026-0001",
                date_added="2026-10-20",
                due_date="2026-11-10",
            )
        }

        findings = build_findings(
            [component],
            {component.purl: ["GHSA-test"]},
            details,
            kev,
            {"CWE-89": "SQLI"},
        )

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].kev)
        self.assertEqual(findings[0].fixed_versions, ("3.2.9",))
        self.assertEqual(findings[0].rule_family, "SQLI")
        self.assertEqual(findings[0].cve_ids, ("CVE-2026-0001",))
        self.assertEqual(findings[0].severity, "high")

    def test_build_findings_puts_kev_ahead_of_higher_cvss(self):
        kev_component = Component("nginx", "1.25.3", "pkg:apk/alpine/nginx@1.25.3")
        critical_component = Component(
            "openssl", "3.0.0", "pkg:apk/alpine/openssl@3.0.0"
        )
        details = {
            "GHSA-kev": {
                "id": "GHSA-kev",
                "aliases": ["CVE-2026-1000"],
                "database_specific": {"severity": "MODERATE"},
            },
            "GHSA-critical": {
                "id": "GHSA-critical",
                "aliases": ["CVE-2026-2000"],
                "database_specific": {"severity": "CRITICAL"},
            },
        }
        kev = {
            "CVE-2026-1000": KeVEntry(
                cve_id="CVE-2026-1000",
                date_added="2026-10-20",
                due_date="2026-10-23",
            )
        }

        findings = build_findings(
            [critical_component, kev_component],
            {
                critical_component.purl: ["GHSA-critical"],
                kev_component.purl: ["GHSA-kev"],
            },
            details,
            kev,
            {},
        )

        self.assertEqual(findings[0].id, "GHSA-kev")
        self.assertEqual(findings[1].id, "GHSA-critical")

    def test_build_findings_handles_missing_osv_details(self):
        component = Component("library", "1.0.0", "pkg:generic/library@1.0.0")

        findings = build_findings(
            [component],
            {component.purl: ["OSV-2026-1"]},
            {},
            {},
            {},
        )

        self.assertEqual(findings[0].summary, "OSV-2026-1")
        self.assertEqual(findings[0].severity, "unknown")


if __name__ == "__main__":
    unittest.main()

