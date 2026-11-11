import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("stage_sources", HERE / "stage_sources.py")
stage_sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_sources)


class StageSourcesTests(unittest.TestCase):
    def test_exact_manifest_stages_closed_23_and_never_adopts(self):
        with tempfile.TemporaryDirectory(prefix="contour-source-stage-") as temporary:
            out = Path(temporary).resolve()
            mounts = stage_sources.stage(ROOT, out)
            self.assertEqual(len(mounts), 4)
            self.assertEqual(len([p for p in out.rglob("*") if p.is_file()]), 23)
            self.assertEqual(len(list(mounts[1].iterdir())), 12)
            self.assertEqual(len(list(mounts[2].iterdir())), 9)
            self.assertEqual(mounts[1].stat().st_mode & 0o777, 0o755)
            self.assertEqual(mounts[0].stat().st_mode & 0o777, 0o644)
            with self.assertRaises(ValueError):
                stage_sources.stage(ROOT, out)

    def test_rejects_source_symlink_and_wrong_digest(self):
        with tempfile.TemporaryDirectory(prefix="contour-source-check-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.write_bytes(b"synthetic")
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(ValueError):
                stage_sources.checked_file(alias)
            with self.assertRaises(ValueError):
                stage_sources.copy_checked(source, root / "output", "0" * 64)
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
