"""Regression tests for the forbidden-domain scanner.

Covers the negative cases that an exact-head review (dot) asked to be checked in:
clean / guard-only scans, hidden files, a filename exemption word (content-only
policy), newline-containing filenames, and missing/scanner-error cases (fail closed).

    python3 -m unittest discover -s .github/scripts -p 'test_forbidden_domain_scan.py' -v

Requires ripgrep on PATH (the workflow provisions it).
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forbidden_domain_scan as fds

# The forbidden string, built from parts so this test file does not itself trip the
# gate it tests (the fixtures below produce the real domain only at runtime).
BAD = "a11oy" ".com"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fdg_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, relpath, content):
        p = os.path.join(self.dir, relpath)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
