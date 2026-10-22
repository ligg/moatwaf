import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from security_automation.sbom import load_components


class SbomTests(unittest.TestCase):
    def test_load_components_deduplicates_purls(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "name": "django",
                                "version": "3.2.0",
                                "purl": "pkg:pypi/django@3.2.0",
                            },
                            {
                                "name": "django",
                                "version": "3.2.0",
                                "purl": "pkg:pypi/django@3.2.0",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            components = load_components(path)

        self.assertEqual(
            [component.purl for component in components],
            ["pkg:pypi/django@3.2.0"],
        )

    def test_load_components_finds_nested_components_and_skips_missing_purl(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {"name": "without-purl", "version": "1.0.0"},
                            {
                                "name": "application",
                                "version": "1.0.0",
                                "components": [
                                    {
                                        "name": "openssl",
                                        "version": "3.0.0",
                                        "purl": "pkg:apk/alpine/openssl@3.0.0",
                                    }
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            components = load_components(path)

        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].name, "openssl")

    def test_load_components_rejects_non_cyclonedx_input(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text('{"components": []}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "CycloneDX"):
                load_components(path)


if __name__ == "__main__":
    unittest.main()

