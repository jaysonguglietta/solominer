"""Argument-boundary tests for the optional root-run manual updater.

Only help and invalid invocations are exercised here. An actual update needs a
separately managed, disposable Fedora host and is never run by these tests.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "manual-update.sh"


def invoke(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


class ManualUpdateArgumentsTests(unittest.TestCase):
    def test_help_describes_explicit_operations_without_privileges(self):
        result = invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        help_text = result.stdout + result.stderr
        for operation in ("--check", "--packages", "--miner", "--all"):
            with self.subTest(operation=operation):
                self.assertIn(operation, help_text)

    def test_unknown_option_is_rejected(self):
        result = invoke("--unexpected")
        self.assertNotEqual(result.returncode, 0)

    def test_mutating_operations_require_a_full_commit_id(self):
        for operation in ("--miner", "--all"):
            for supplied in ((), ("main",), ("abc123",), ("g" * 40,), ("A" * 40,)):
                with self.subTest(operation=operation, supplied=supplied):
                    result = invoke(operation, *supplied)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA", (result.stdout + result.stderr).upper())

    def test_extra_arguments_are_rejected(self):
        for arguments in (("--check", "extra"), ("--packages", "extra"),
                          ("--miner", "a" * 40, "extra"),
                          ("--all", "a" * 40, "extra")):
            with self.subTest(arguments=arguments):
                result = invoke(*arguments)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
