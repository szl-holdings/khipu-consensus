"""Regression tests for the forbidden-domain scanner.

Covers the negative cases that exact-head reviews (dot) asked to be checked in:
clean / guard-only scans, hidden files, a filename exemption word (content-only
policy), newline-containing filenames, missing/scanner-error cases (fail closed),
and the per-occurrence guard shapes: URL punctuation, identifiers and other call
arguments supply no guard; legitimate BLOCKLIST, assertNotIn, keyed and prose
prohibitions stay exempt; lexer constructs cannot hide a call's parenthesis.

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


class TestPerOccurrenceGuard(Base):
    """Exemption is judged per occurrence, from explicit prohibition shapes only
    (exact-head HOLD on khipu-consensus#45, comment 6216658526)."""

    def assert_flagged(self, relpath, source):
        self.write(relpath, source)
        self.assertEqual(len(self.violations()), 1, source)

    def assert_exempt(self, relpath, source):
        self.write(relpath, source)
        self.assertEqual(self.violations(), [], source)

    # -- dot's four fixtures: URL punctuation and identifiers supply nothing --------
    def test_semicolon_inside_quoted_reference_is_flagged(self):
        self.assert_flagged("app.js", f'fetch("https://{BAD}/;blocklist")\n')

    def test_comma_inside_quoted_reference_is_flagged(self):
        self.assert_flagged("app.js", f'fetch("https://{BAD}/?x=1,forbidden")\n')

    def test_parenthesis_inside_quoted_reference_is_flagged(self):
        self.assert_flagged("app.js", f'fetch("https://{BAD}/(never)")\n')

    def test_underscore_identifier_does_not_supply_a_guard(self):
        self.assert_flagged("app.js", f'forbidden_url = fetch("https://{BAD}")\n')

    def test_camel_case_identifier_does_not_supply_a_guard(self):
        self.assert_flagged("app.py", f'neverHost = "{BAD}"\n')

    # -- a guard word in another argument of a live call covers nothing --------------
    def test_guard_word_in_options_argument_is_flagged(self):
        self.assert_flagged("app.js", f'fetch("https://{BAD}", {{cache: "never"}})\n')

    def test_guard_word_in_separate_argument_is_flagged(self):
        self.assert_flagged("app.py", f'requests.get("https://{BAD}", params="forbidden")\n')

    def test_guard_named_keyword_argument_is_flagged(self):
        self.assert_flagged("app.py", f'requests.get(never="https://{BAD}")\n')

    def test_guard_named_keyword_argument_across_lines_is_flagged(self):
        self.assert_flagged("app.py", f'requests.get(\n    never="https://{BAD}",\n)\n')

    def test_guard_keyed_object_passed_to_a_call_is_flagged(self):
        self.assert_flagged("app.js", f'fetch(url, {{never: "https://{BAD}"}})\n')

    def test_value_chained_onto_guard_constant_is_flagged(self):
        self.assert_flagged("app.js", f'const BLOCKLIST = ["https://{BAD}"].map(fetch)\n')

    def test_value_chained_on_the_next_line_is_flagged(self):
        self.assert_flagged("app.js", f'const BLOCKLIST = ["https://{BAD}"]\n  .map(fetch)\n')

    # -- a genuine guard does not cover a separate live reference on the same line ---
    def test_guard_constant_plus_live_call_on_one_line_is_flagged(self):
        self.assert_flagged("app.js", f'const NEVER = "{BAD}"; fetch("https://{BAD}")\n')

    def test_trailing_guard_comment_does_not_cover_live_call(self):
        self.assert_flagged("app.py", f'requests.get("https://{BAD}")  # never\n')

    def test_locator_string_with_prose_guard_is_flagged(self):
        self.assert_flagged("app.js", f'fetch("https://{BAD}/ never")\n')

    def test_escaped_locator_string_with_prose_guard_is_flagged(self):
        self.assert_flagged("app.py", f'body = "https:\\/\\/{BAD} never"\n')

    def test_shell_argument_guard_word_is_flagged(self):
        self.assert_flagged("run.sh", f"curl https://{BAD} never\n")

    def test_shell_option_named_like_a_guard_is_flagged(self):
        self.assert_flagged("run.sh", f"curl --never=https://{BAD}\n")

    def test_shell_argument_shaped_like_a_binding_is_flagged(self):
        self.assert_flagged("run.sh", f'curl -H never="https://{BAD}"\n')

    def test_stylesheet_url_with_guard_comment_is_flagged(self):
        self.assert_flagged("site.css", f".x {{ background: url(//{BAD}/x) }} /* never */\n")

    def test_markdown_link_target_with_prose_guard_is_flagged(self):
        self.assert_flagged("README.md", f"Never [here](https://{BAD}).\n")

    def test_guard_after_markup_inside_a_prose_url_is_flagged(self):
        self.assert_flagged("NOTES.md", f"See https://{BAD}/<never> for details.\n")
        self.assert_flagged("NOTES.md", f"Mirror https://{BAD} at https://example.org/never too.\n")

    def test_markdown_link_definition_is_flagged(self):
        self.assert_flagged("README.md", f"[never]: https://{BAD}\n")

    def test_markdown_fenced_shell_is_code(self):
        self.assert_flagged("README.md", f"Run:\n\n```sh\ncurl https://{BAD} never\n```\n")

    def test_html_link_target_with_guard_text_is_flagged(self):
        self.assert_flagged("index.html", f'<a href="https://{BAD}">never</a>\n')

    # -- prose may name the bare host, never carry a URL to it --------------------
    def test_inline_script_url_with_guard_text_is_flagged(self):
        self.assert_flagged("index.html", f"<script>fetch('https://{BAD}') // never</script>\n")

    def test_comment_url_with_guard_word_is_flagged(self):
        self.assert_flagged("app.js", f"// never call https://{BAD}\n")

    def test_prose_url_with_guard_word_is_flagged(self):
        self.assert_flagged("NOTES.md", f"Never use https://{BAD} in a page.\n")

    # -- the lexer cannot be steered into hiding a call's parenthesis ---------------
    def test_regex_literal_cannot_close_a_call(self):
        self.assert_flagged("app.js", f'fetch(/)/, {{never: "https://{BAD}"}})\n')

    def test_line_start_slash_cannot_close_a_call(self):
        self.assert_flagged("app.js", f'fetch(\n/)/, {{never: "https://{BAD}"}})\n')

    def test_division_is_not_a_regex_literal(self):
        self.assert_exempt("app.js", f'const half = total / 2 / 1; const NEVER = "https://{BAD}";\n')

    def test_jsx_text_cannot_close_a_call(self):
        self.assert_flagged("app.jsx", f'fetch(<div>)</div>, {{never: "https://{BAD}"}})\n')

    def test_lua_block_comment_cannot_close_a_call(self):
        self.assert_flagged("app.lua", f'fetch(--[[\n)\n]]\n{{never="https://{BAD}"}})\n')

    # -- legitimate prohibition shapes stay exempt --------------------------------
    def test_blocklist_constant_in_code_is_exempt(self):
        self.assert_exempt("guard.py", f'BLOCKLIST = ["https://{BAD}"]\n')

    def test_multiline_blocklist_needs_the_guard_on_each_line(self):
        # Unchanged contract: the guard must be stated on the same line as the host.
        self.assert_flagged("guard.py", f'BLOCKLIST = [\n    "https://{BAD}",\n]\n')

    def test_guard_named_constants_are_exempt(self):
        self.assert_exempt("guard.py", f'FORBIDDEN_PUBLIC_HOST = "{BAD}"\nNEVER = "https://{BAD}"\n')
        self.assert_exempt("guard.ts", f'export const NEVER = "https://{BAD}";\n')

    def test_guard_named_comparison_is_exempt(self):
        self.assert_exempt("test_guard.py", f'assert cd.FORBIDDEN_PUBLIC_HOST == "{BAD}"\n')

    def test_assert_not_in_code_is_exempt(self):
        self.assert_exempt("test_guard.py", f'self.assertNotIn("{BAD}", text)\n')

    def test_not_in_assertion_is_exempt(self):
        self.assert_exempt("test_guard.py", f'assert "https://{BAD}" not in page.text\n')

    def test_prose_string_naming_the_host_is_exempt(self):
        self.assert_exempt("test_guard.py", f'self.assertIn("Never {BAD}.", page)\n')

    def test_code_comment_is_exempt(self):
        self.assert_exempt("guard.py", f"# Never set Location to {BAD}.\n")

    def test_multiline_docstring_line_is_exempt(self):
        self.assert_exempt("guard.py", f'def f():\n    """Product canonical.\n\n    {BAD} is never that canonical.\n    """\n')

    def test_keyed_json_is_exempt(self):
        self.assert_exempt("estate.json", f'{{"never": "{BAD}", "list": {{"never": ["{BAD}"]}}}}\n')
        self.assert_exempt("estate.json", f'{{\n  "never": ["{BAD}"],\n  "never_host": "{BAD} furniture-shop domain"\n}}\n')

    def test_keyed_json_value_on_a_later_line_is_flagged(self):
        self.assert_flagged("estate.json", f'{{\n  "never": [\n    "{BAD}"\n  ]\n}}\n')

    def test_keyed_yaml_is_exempt(self):
        self.assert_exempt("estate.yml", f"honesty:\n  never: {BAD}  # foreign storefront\n")

    def test_html_text_comment_and_attribute_are_exempt(self):
        self.assert_exempt("index.html", f"<li>Never {BAD}.</li>\n")
        self.assert_exempt("index.html", f'<meta property="og:description" content="Product stays on a-11-oy.com. Never {BAD}." />\n')
        self.assert_exempt("index.html", f"<!-- This origin = proof. Never {BAD}. -->\n")

    def test_html_definition_row_is_exempt(self):
        self.assert_exempt("index.html", f'<div><span class="k">never</span><span class="v">{BAD}</span></div>\n')

    def test_guard_word_in_an_html_attribute_value_is_not_text(self):
        self.assert_flagged("index.html", f'<span class="never">{BAD}</span>\n')

    def test_markdown_prose_and_table_are_exempt(self):
        self.assert_exempt("README.md", f"Never `{BAD}`.\n| {BAD} | NEVER | Not a surface of this project. |\n")

    def test_every_occurrence_covered_on_one_line_is_exempt(self):
        self.assert_exempt("estate.json", f'{{"never": "{BAD}", "note": "Two origins only. Never {BAD}."}}\n')

    # -- stricter than before: these lines used to pass and now need a real guard ----
    def test_positive_disclosure_assertion_with_guard_comment_is_flagged(self):
        self.assert_flagged("test_page.py", f'assert "{BAD}" in PAGE  # never-origin disclosure\n')

    def test_guard_named_function_argument_is_flagged(self):
        self.assert_flagged("test_page.py", f'assert cd._is_forbidden_public_host("{BAD}")\n')


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
