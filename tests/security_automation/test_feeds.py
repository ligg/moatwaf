import json
import unittest
from urllib.request import Request

from security_automation.feeds import fetch_kev, query_osv


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class FeedTests(unittest.TestCase):
    def test_fetch_kev_indexes_cves(self):
        def opener(request, timeout):
            self.assertIsInstance(request, Request)
            self.assertGreater(timeout, 0)
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-0001",
                            "dateAdded": "2026-10-20",
                            "dueDate": "2026-10-23",
                            "requiredAction": "Apply updates.",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ]
                }
            )

        entries = fetch_kev(opener=opener)

        self.assertEqual(entries["CVE-2026-0001"].due_date, "2026-10-23")

    def test_query_osv_builds_batch_queries(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 30)
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(
                body["queries"],
                [{"package": {"purl": "pkg:pypi/django@3.2.0"}}],
            )
            return FakeResponse({"results": [{"vulns": [{"id": "GHSA-test"}]}]})

        matches = query_osv(["pkg:pypi/django@3.2.0"], opener=opener)

        self.assertEqual(matches, {"pkg:pypi/django@3.2.0": ["GHSA-test"]})


if __name__ == "__main__":
    unittest.main()

