import hashlib
import json
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.build_rule_pack import build_rule_pack, main


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RulePackTests(unittest.TestCase):
    def test_rule_pack_is_deterministic_and_contains_manifest(self):
        with TemporaryDirectory() as tmp:
            output_a = Path(tmp) / "a"
            output_b = Path(tmp) / "b"
            first = build_rule_pack(Path("conf/rules"), output_a, "v1.0.0")
            second = build_rule_pack(Path("conf/rules"), output_b, "v1.0.0")

            self.assertEqual(sha256(first.archive), sha256(second.archive))
            self.assertEqual(first.sha256, sha256(first.archive))

            with tarfile.open(first.archive, "r:gz") as archive:
                names = archive.getnames()
                manifest_name = next(name for name in names if name.endswith("/manifest.json"))
                manifest = json.load(archive.extractfile(manifest_name))

        self.assertEqual(manifest["version"], "v1.0.0")
        self.assertIn("sql_injection.yaml", manifest["files"])
        self.assertGreaterEqual(len(manifest["files"]), 9)

    def test_default_rule_pack_uses_the_runtime_rule_corpus(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            self.assertEqual(
                main(["--output-dir", str(output), "--version", "v1.0.0"]),
                0,
            )

            archive_path = output / "moat-waf-rules-v1.0.0.tar.gz"
            with tarfile.open(archive_path, "r:gz") as archive:
                rule_name = next(
                    name for name in archive.getnames()
                    if name.endswith("/rules/sql_injection.yaml")
                )
                sql_rules = archive.extractfile(rule_name).read().decode("utf-8")

        self.assertIn("id: SQLI-001", sql_rules)
        self.assertNotIn("id: SQLI_001", sql_rules)
        self.assertIn("action: BLOCK", sql_rules)

    def test_rule_pack_rejects_unsafe_version(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "version"):
                build_rule_pack(Path("conf/rules"), Path(tmp), "../escape")


if __name__ == "__main__":
    unittest.main()

