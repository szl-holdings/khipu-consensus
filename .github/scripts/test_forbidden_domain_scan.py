"""Regression tests for the forbidden-domain scanner.

Covers the negative cases that an exact-head review (dot) asked to be checked in:
clean / guard-only scans, hidden files, a filename exemption word (content-only
policy), newline-containing filenames, and missing/scanner-error cases (fail closed).

    python3 -m unittest discover -s .github/scripts -p 'test_forbidden_domain_scan.py' -v

Requires ripgrep on PATH (the workflow provisions it).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forbidden_domain_scan as fds

# The forbidden string, built from parts so this test file does not itself trip the
# gate it tests (the fixtures below produce the real domain only at runtime).
BAD = "a11oy" ".com"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fdg_")
        subprocess.run(["git", "init", "-q", self.dir], check=True)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, relpath, content, *, tracked=True):
        p = os.path.join(self.dir, relpath)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        if tracked:
            subprocess.run(["git", "-C", self.dir, "add", "-f", "--", relpath], check=True)
        return p

    def violations(self):
        return fds.scan_root(self.dir)


class TestCleanAndCanonical(Base):
    def test_no_forbidden_domain_is_clean(self):
        self.write("src/app.js", "const u = 'https://a-11-oy.com'; // product surface\n")
        self.write("docs/proof.md", "Proof lives at https://a11oy.net today.\n")
        self.assertEqual(self.violations(), [])

    def test_canonical_and_hyphen_prefixed_surfaces_not_flagged(self):
        self.write("a.txt", "a-11-oy.com\n")   # product surface (hyphenated)
        self.write("b.txt", "a11oy.net\n")     # proof surface (.net)
        self.write("c.txt", "see -a11oy.com\n")  # hyphen immediately before -> lookbehind excludes
        self.assertEqual(self.violations(), [])


class TestViolations(Base):
    def test_forbidden_domain_in_source_is_flagged(self):
        self.write("src/app.js", f"fetch('https://{BAD}/api')\n")
        v = self.violations()
        self.assertEqual(len(v), 1)
        self.assertTrue(v[0][0].endswith(b"src/app.js"))


class TestExemptionIsContentOnly(Base):
    def test_guard_word_on_same_line_is_exempt(self):
        self.write("src/guard.js", f"// {BAD} must never appear as a surface\n")
        self.assertEqual(self.violations(), [])

    def test_exemption_word_in_path_does_not_exempt_content(self):
        # identical prohibited content under a 'blocklist/' path must STILL fail:
        # the exemption is judged on the source line only, never the filename.
        self.write("blocklist/app.js", f"fetch('https://{BAD}')\n")
        v = self.violations()
        self.assertEqual(len(v), 1)
        self.assertIn(b"blocklist/app.js", v[0][0])


class TestGuardWordInsideExecutableReference(Base):
    """A guard word that only appears inside the prohibited URL or value is not a
    guard context (exact-head HOLD on khipu-consensus#45, comment 6204962226)."""

    def assert_flagged(self, source):
        self.write("src/live.js", source)
        self.assertEqual(len(self.violations()), 1, source)

    def assert_exempt(self, source):
        self.write("docs/guard.md", source)
        self.assertEqual(self.violations(), [], source)

    def test_guard_word_as_url_path_segment_is_flagged(self):
        self.assert_flagged(f'fetch("https://{BAD}/blocklist")\n')

    def test_guard_word_as_query_value_is_flagged(self):
        self.assert_flagged(f'url = "https://{BAD}/?mode=forbidden"\n')

    def test_guard_word_as_subdomain_value_is_flagged(self):
        self.assert_flagged(f'host = "never.{BAD}"\n')

    def test_guard_word_inside_markdown_link_target_is_flagged(self):
        self.assert_flagged(f"[docs](https://{BAD}/blocklist)\n")

    def test_guard_substring_inside_identifier_is_flagged(self):
        self.assert_flagged(f'forbiddenFruit = fetch("https://{BAD}")\n')

    def test_non_guard_word_containing_guard_text_is_flagged(self):
        self.assert_flagged(f"nevertheless we call https://{BAD} here\n")

    def test_blocklist_declaration_outside_the_reference_is_exempt(self):
        self.assert_exempt(f'BLOCKLIST = ["https://{BAD}"]\n')

    def test_assert_not_in_guard_is_exempt(self):
        self.assert_exempt(f'self.assertNotIn("{BAD}", surfaces)\n')

    def test_prose_prohibition_is_exempt(self):
        self.assert_exempt(f"{BAD} is not a surface; it appears only in blocklists.\n")


class TestHiddenScope(Base):
    def test_hidden_file_is_scanned(self):
        self.write(".github/config.txt", f"endpoint = https://{BAD}\n")
        self.assertEqual(len(self.violations()), 1)


class TestNewlineFilename(Base):
    def test_newline_in_filename_is_not_split(self):
        # a newline-containing filename must be handled as ONE path (structured JSON),
        # not split into two by a line-based file list.
        self.write("weird\nname.txt", f"x = '{BAD}'\n")
        v = self.violations()
        self.assertEqual(len(v), 1)
        self.assertIn(b"\n", v[0][0])   # the path legitimately contains the newline, intact


class TestFailClosed(Base):
    def test_git_timeout_fails_closed_with_a_bounded_deadline(self):
        with unittest.mock.patch.object(fds.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 30)) as run:
            with self.assertRaises(SystemExit) as cm:
                self.violations()
        self.assertEqual(cm.exception.code, 2)
        self.assertTrue(0 < run.call_args.kwargs["timeout"] <= 60)

    def test_ripgrep_timeout_fails_closed_with_a_bounded_deadline(self):
        with unittest.mock.patch.object(fds.subprocess, "run", side_effect=subprocess.TimeoutExpired("rg", 30)) as run:
            with self.assertRaises(SystemExit) as cm:
                fds.rg(["--version"])
        self.assertEqual(cm.exception.code, 2)
        self.assertTrue(0 < run.call_args.kwargs["timeout"] <= 60)

    def test_scanner_error_fails_closed(self):
        with self.assertRaises(SystemExit) as cm:
            fds.scan_root(os.path.join(self.dir, "no-such-path"))
        self.assertEqual(cm.exception.code, 2)

    def test_missing_ripgrep_fails_closed(self):
        original = fds.RG
        try:
            fds.RG = "rg-definitely-not-installed-xyz"
            with self.assertRaises(SystemExit) as cm:
                fds.scan_root(self.dir)
            self.assertEqual(cm.exception.code, 2)
        finally:
            fds.RG = original


class TestTrackedSourceScope(Base):
    def test_binary_source_with_token_after_nul_is_not_silently_skipped(self):
        path = self.write("data.bin", "")
        for padding in (b"", b"\n", b"X" * 200000 + b"\n"):
            with self.subTest(padding_bytes=len(padding)):
                with open(path, "wb") as stream:
                    stream.write(b"prefix\0" + padding + b"https://" + BAD.encode() + b"\n")
                self.assertEqual(len(self.violations()), 1)

    def test_dash_filename_is_not_stdin(self):
        self.write("-", f"endpoint = 'https://{BAD}'\n")
        self.assertEqual(len(self.violations()), 1)

    def test_gitignored_tracked_source_cannot_escape(self):
        self.write(".gitignore", "src/\n")
        self.write("src/app.py", f"endpoint = 'https://{BAD}'\n")
        self.assertEqual(len(self.violations()), 1)

    def test_ripgrep_ignore_cannot_hide_tracked_hidden_source(self):
        self.write(".ignore", ".github/\n")
        self.write(".github/config.txt", f"endpoint = 'https://{BAD}'\n")
        self.assertEqual(len(self.violations()), 1)

    def test_ripgrep_configuration_cannot_hide_tracked_source(self):
        config = self.write("local-rg-config", "--glob=!*.py\n", tracked=False)
        self.write("app.py", f"endpoint = 'https://{BAD}'\n")
        with unittest.mock.patch.dict(os.environ, {"RIPGREP_CONFIG_PATH": config}):
            self.assertEqual(len(self.violations()), 1)

    def test_untracked_generated_content_is_outside_scope(self):
        self.write("build/generated.txt", f"endpoint = 'https://{BAD}'\n", tracked=False)
        self.assertEqual(self.violations(), [])

    def test_deleted_tracked_source_fails_closed(self):
        path = self.write("app.py", "clean\n")
        os.unlink(path)
        with self.assertRaises(SystemExit) as cm:
            self.violations()
        self.assertEqual(cm.exception.code, 2)

    def test_regular_tracked_source_replaced_by_symlink_fails_closed(self):
        path = self.write("app.py", "clean\n")
        target = self.write("target", "clean\n", tracked=False)
        os.unlink(path)
        os.symlink(target, path)
        with self.assertRaises(SystemExit) as cm:
            self.violations()
        self.assertEqual(cm.exception.code, 2)

    def test_tracked_symlink_is_not_followed(self):
        target = self.write("untracked-target", f"endpoint = 'https://{BAD}'\n", tracked=False)
        os.symlink(target, os.path.join(self.dir, "source-link"))
        subprocess.run(["git", "-C", self.dir, "add", "--", "source-link"], check=True)
        self.assertEqual(self.violations(), [])

    def test_multiple_batches_keep_every_tracked_match(self):
        for index in range(130):
            self.write(f"sources/{index}.txt", f"endpoint = 'https://{BAD}'\n")
        self.assertEqual(len(self.violations()), 130)


if __name__ == "__main__":
    unittest.main(verbosity=2)
