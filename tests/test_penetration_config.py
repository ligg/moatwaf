import os
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("penetration_test.py")


class PenetrationConfigTests(unittest.TestCase):
    def run_config_check(self, token: str | None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("PENTEST_ADMIN_TOKEN", None)
        if token is not None:
            env["PENTEST_ADMIN_TOKEN"] = token
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--check-config"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_missing_admin_token_fails_configuration_check(self):
        result = self.run_config_check(None)

        self.assertEqual(result.returncode, 2)
        self.assertIn("PENTEST_ADMIN_TOKEN", result.stderr)
        self.assertNotIn("目标不可达", result.stdout)

    def test_admin_token_is_read_from_environment(self):
        result = self.run_config_check("a" * 32)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("configuration OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
