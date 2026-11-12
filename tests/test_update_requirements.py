import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OLD = (
    "jupyterhub==1.0\ncachetools==7.0\nremoved==1.0\n\n"
    "# --- jjsc customizations (own packages + their new transitive deps) ---\n\n"
    "custom==1.0\n\n\n# Pinned manually\nsetuptools==1.0\n"
)
UPSTREAM = "jupyterhub==2.0\ncachetools==8.0\nadded==1.0\n"
SIDECAR = "# sidecar\njupyterhub==1.0\ncachetools==7.0\nsetuptools==1.0\n"


class UpdateRequirementsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("unfrozen", "sidecar", "bin"):
            (self.root / directory).mkdir()
        shutil.copy(ROOT / "update-requirements.sh", self.root)
        (self.root / "requirements_upstream.txt").write_text(OLD)
        (self.root / "sidecar" / "requirements_pip.txt").write_text(SIDECAR)
        (self.root / "unfrozen" / "requirements-jsc.txt").write_text("custom==1.*\n")
        (self.root / "overrides.txt").write_text("cachetools==8.0\n")
        (self.root / "upstream.txt").write_text(UPSTREAM)
        docker = self.root / "bin" / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "test \"$FAKE_DOCKER_FAIL\" != 1 || exit 1\n"
            "work=${4%:/work}\n"
            "grep -q '^jupyterhub==2.0$' \"$work/constraints.txt\" || exit 1\n"
            "printf 'custom==1.1\\n    # via -r unfrozen/requirements-jsc.txt\\n' > \"$work/compiled.txt\"\n"
        )
        docker.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
            "REQUIREMENTS_BASE_URL": (self.root / "upstream.txt").as_uri(),
        }

    def run_update(self, *args, env=None):
        return subprocess.run(
            ["bash", str(self.root / "update-requirements.sh"), *args],
            cwd=self.root, env=env or self.env, text=True, capture_output=True,
        )

    def test_apply_refreshes_and_reports_both_files(self):
        result = self.run_update("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        hub = (self.root / "requirements_upstream.txt").read_text()
        self.assertTrue(hub.startswith(UPSTREAM), hub)
        self.assertIn("custom==1.1", hub)
        self.assertIn("# Pinned manually\nsetuptools==1.0", hub)
        self.assertNotIn("removed==", hub)
        self.assertEqual(
            (self.root / "sidecar" / "requirements_pip.txt").read_text(),
            SIDECAR.replace("jupyterhub==1.0", "jupyterhub==2.0")
            .replace("cachetools==7.0", "cachetools==8.0"),
        )
        self.assertEqual((self.root / "overrides.txt").read_text(), "cachetools==8.0\n")
        report = (self.root / "requirements-update-report.md").read_text()
        for row in ("| cachetools | 7.0 | 8.0 |", "| added | - | 1.0 |",
                    "| removed | 1.0 | - |", "| custom | 1.0 | 1.1 |",
                    "## Sidecar Python pins"):
            self.assertIn(row, report)

    def test_dry_run_does_not_change_tracked_requirements(self):
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "requirements_upstream.txt").read_text(), OLD)
        self.assertEqual((self.root / "sidecar" / "requirements_pip.txt").read_text(), SIDECAR)
        self.assertIn("| cachetools | 7.0 | 8.0 |",
                      (self.root / "requirements-update-report.md").read_text())

    def test_invalid_fetch_and_compile_failure_do_not_change_files(self):
        for broken in ("fetch", "compile", "missing-sidecar", "footer-conflict"):
            with self.subTest(broken=broken):
                (self.root / "upstream.txt").write_text({
                    "fetch": "<html>error</html>",
                    "missing-sidecar": "jupyterhub==2.0\n",
                    "footer-conflict": UPSTREAM + "setuptools==2.0\n",
                }.get(broken, UPSTREAM))
                env = {**self.env, "FAKE_DOCKER_FAIL": "1" if broken == "compile" else "0"}
                result = self.run_update("--yes", env=env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual((self.root / "requirements_upstream.txt").read_text(), OLD)
                self.assertEqual((self.root / "sidecar" / "requirements_pip.txt").read_text(), SIDECAR)

    def test_report_is_replaced_when_no_python_pins_change(self):
        (self.root / "requirements-update-report.md").write_text("stale report")
        result = self.run_update("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_update("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.root / "requirements-update-report.md").read_text()
        self.assertNotIn("stale report", report)
        self.assertNotIn("| cachetools | 7.0 | 8.0 |", report)
        self.assertIn("_no pin changes_", report)


if __name__ == "__main__":
    unittest.main()
