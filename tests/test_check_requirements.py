import contextlib
import io
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "check-requirements.py"


class OverrideCheckTest(unittest.TestCase):
    def run_check(self, frozen, upstream, override):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unfrozen").mkdir()
            shutil.copyfile(SCRIPT, root / SCRIPT.name)
            (root / "requirements_upstream.txt").write_text(frozen)
            (root / "unfrozen" / "requirements-jsc.txt").write_text("")
            (root / "overrides.txt").write_text(override)
            output = io.StringIO()
            with patch("urllib.request.urlopen", return_value=io.BytesIO(upstream.encode())):
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as result:
                        runpy.run_path(str(root / SCRIPT.name), run_name="__main__")
            return result.exception.code, output.getvalue()

    def test_upstream_at_or_above_override(self):
        for upstream_version in ("8.0", "8.0.0", "9.0.0"):
            with self.subTest(upstream_version=upstream_version):
                code, output = self.run_check(
                    "cachetools==7.3.0\n",
                    f"cachetools=={upstream_version}\n",
                    "cachetools==8.0.0\n",
                )
                self.assertEqual(code, 1)
                self.assertIn(f"cachetools==7.3.0 vs upstream cachetools=={upstream_version}", output)
                self.assertIn(f"upstream z2jh is already at {upstream_version}", output)
                self.assertIn("merge the upstream pin before removing the override", output)

    def test_upstream_behind_override(self):
        code, output = self.run_check(
            "cachetools==7.3.0\n", "cachetools==7.3.0\n", "cachetools==8.0.0\n"
        )
        self.assertEqual(code, 0, output)

    def test_frozen_caught_up(self):
        code, output = self.run_check(
            "cachetools==8.0.0\n", "cachetools==8.0.0\n", "cachetools==8.0.0\n"
        )
        self.assertEqual(code, 1)
        self.assertIn("the frozen file is already at 8.0.0", output)

    def test_upstream_caught_up_with_no_frozen_pin(self):
        code, output = self.run_check(
            "", "cachetools==8.0.0\n", "cachetools==8.0.0\n"
        )
        self.assertEqual(code, 1)
        self.assertIn("upstream z2jh is already at 8.0.0", output)


if __name__ == "__main__":
    unittest.main()
