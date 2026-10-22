import hashlib
import json
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.build_rule_pack import build_rule_pack


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RulePackTests(unittest.TestCase):
    def test_rule_pack_is_deterministic_and_contains_manifest(self):
        with TemporaryDirectory() as tmp:
            output_a = Path(tmp) / "a"
            output_b = Path(tmp) / "b"
            first = build_rule_pack(Path("rules"), output_a, "v1.0.0")
            second = build_rule_pack(Path("rules"), output_b, "v1.0.0")

            self.assertEqual(sha256(first.archive), sha256(second.archive))
            self.assertEqual(first.sha256, sha256(first.archive))

            with tarfile.open(first.archive, "r:gz") as archive:
                names = archive.getnames()
                manifest_name = next(name for name in names if name.endswith("/manifest.json"))
                manifest = json.load(archive.extractfile(manifest_name))

        self.assertEqual(manifest["version"], "v1.0.0")
        self.assertIn("sql_injection.yaml", manifest["files"])
        self.assertGreaterEqual(len(manifest["files"]), 9)

    def test_rule_pack_rejects_unsafe_version(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "version"):
                build_rule_pack(Path("rules"), Path(tmp), "../escape")


if __name__ == "__main__":
    unittest.main()

