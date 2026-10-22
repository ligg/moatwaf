import unittest

from security_automation.report import render_issue, render_report


def finding(
    finding_id,
    *,
    cve="CVE-2026-0001",
    severity="high",
    kev=False,
    rule_family="SQLI",
):
    return {
        "id": finding_id,
        "aliases": [cve],
        "cveIds": [cve],
        "summary": f"Summary for {finding_id}",
        "component": "django",
        "version": "3.2.0",
        "purl": "pkg:pypi/django@3.2.0",
        "severity": severity,
        "fixedVersions": ["3.2.9"],
        "kev": kev,
        "kevDueDate": "2026-10-23" if kev else None,
        "references": ["https://example.test/advisory"],
        "cweIds": ["CWE-89"],
        "ruleFamily": rule_family,
    }


class ReportTests(unittest.TestCase):
    def test_render_report_prioritizes_known_exploited_findings(self):
        scan = {
            "generatedAt": "2026-10-22T00:00:00Z",
            "findings": [
                finding("GHSA-critical", cve="CVE-2026-0002", severity="critical"),
                finding("GHSA-kev", cve="CVE-2026-0001", kev=True),
            ],
            "errors": [],
        }

        report = render_report(scan)

        self.assertLess(report.index("CVE-2026-0001"), report.index("CVE-2026-0002"))
        self.assertIn("Known exploited", report)
        self.assertIn("fixed version", report.lower())

    def test_render_issue_keeps_only_actionable_findings(self):
        scan = {
            "generatedAt": "2026-10-22T00:00:00Z",
            "findings": [
                finding("GHSA-kev", cve="CVE-2026-0001", kev=True),
                finding("GHSA-low", cve="CVE-2026-0002", severity="low"),
            ],
            "errors": [],
        }

        issue = render_issue(scan)

        self.assertIn("CVE-2026-0001", issue)
        self.assertNotIn("CVE-2026-0002", issue)
        self.assertIn("Automatically generated", issue)


if __name__ == "__main__":
    unittest.main()

