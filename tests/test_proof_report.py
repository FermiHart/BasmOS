# SPDX-License-Identifier: BSD-3-Clause
"""Offline regression checks for proof-report status and artifact integrity."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "proof_report.py"
SPEC = importlib.util.spec_from_file_location("basmos_proof_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Child:
    def __init__(self, code):
        self.code = code
        self.stdout = io.StringIO("fixture gate output\n")

    def wait(self):
        return self.code

    def poll(self):
        return self.code


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="basmos-proof-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        manifest = []
        for name, size in MODULE.IMAGES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = bytes([size % 251]) * size
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            manifest.append(f"{digest}  {name}\n")
        (self.root / "SHA256SUMS").write_text("".join(manifest), encoding="ascii")

    def exercise(self, child_exit=0):
        with (
            mock.patch.object(MODULE, "ROOT", self.root),
            mock.patch.object(MODULE.subprocess, "Popen", return_value=Child(child_exit)),
            mock.patch.object(MODULE.sys, "argv", ["proof_report.py"]),
        ):
            result = MODULE.main()
        report = json.loads(
            (self.root / "evidence" / "PROOF-REPORT.json").read_text(encoding="utf-8")
        )
        return result, report

    def test_success_records_five_verified_images(self):
        code, report = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["artifacts"]), 5)
        self.assertTrue(all(x["sha256_matches_manifest"] for x in report["artifacts"]))
        self.assertIn(
            "fixture gate output",
            (self.root / "evidence" / "PROOF-REPORT.log").read_text(encoding="utf-8"),
        )

    def test_nonzero_gate_cannot_pass(self):
        code, report = self.exercise(child_exit=17)
        self.assertEqual(code, 17)
        self.assertEqual(report["status"], "FAIL")

    def test_corrupted_image_cannot_pass(self):
        (self.root / "basmos.bin").write_bytes(b"x" * 512)
        code, report = self.exercise(child_exit=0)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["artifacts"][0]["sha256_matches_manifest"])

    def test_alternate_command_is_rejected(self):
        with (
            mock.patch.object(MODULE, "ROOT", self.root),
            mock.patch.object(MODULE.sys, "argv", ["proof_report.py", "--", "true"]),
        ):
            self.assertEqual(MODULE.main(), 2)
        self.assertFalse((self.root / "evidence" / "PROOF-REPORT.json").exists())


if __name__ == "__main__":
    unittest.main()
