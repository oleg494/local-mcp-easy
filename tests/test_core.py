import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import normalized_program_name, resolve_program, safe_path, should_skip


class SafePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_relative_path_is_allowed(self):
        self.assertEqual(safe_path(self.base, "a/b.txt"), self.base / "a" / "b.txt")

    def test_parent_escape_is_rejected(self):
        with self.assertRaises(ValueError):
            safe_path(self.base, "../secret.txt")

    def test_absolute_escape_is_rejected(self):
        outside = self.base.parent / "secret.txt"
        with self.assertRaises(ValueError):
            safe_path(self.base, outside)

    def test_cyrillic_path_is_allowed(self):
        self.assertEqual(
            safe_path(self.base, "папка/файл.txt"), self.base / "папка" / "файл.txt"
        )

    def test_symlink_escape_is_rejected(self):
        outside = self.base.parent / "outside-target"
        outside.mkdir(exist_ok=True)
        link = self.base / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation requires privileges on this system")
        with self.assertRaises(ValueError):
            safe_path(self.base, "link/secret.txt")


class ProgramNameTests(unittest.TestCase):
    def test_windows_suffixes_are_removed(self):
        self.assertEqual(normalized_program_name("PYTHON.EXE"), "python")
        self.assertEqual(normalized_program_name("npm.cmd"), "npm")

    def test_plain_name_is_preserved(self):
        self.assertEqual(normalized_program_name("git"), "git")

    def test_disallowed_program_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_program(Path.cwd(), "curl", {"python"})

    def test_allowed_program_is_resolved_from_path(self):
        resolved = resolve_program(Path.cwd(), "python", {"python"})
        self.assertTrue(Path(resolved).is_file())


class ExcludeTests(unittest.TestCase):
    def test_hidden_is_skipped_by_default(self):
        self.assertTrue(should_skip(Path(".git"), False, set()))

    def test_hidden_can_be_included(self):
        self.assertFalse(should_skip(Path(".env"), True, set()))

    def test_named_exclusion_always_wins(self):
        self.assertTrue(should_skip(Path("node_modules"), True, {"node_modules"}))


if __name__ == "__main__":
    unittest.main()
