#!/usr/bin/env python3
"""Release-blocking CRITICAL forbidden-domain scanner for the szl-holdings estate.

Rule (validated on the live org): a line matching

    (?<!-)a11oy\\.com

is a violation UNLESS the same line is a prohibition/guard context: outside the
prohibited reference itself, the line contains a standalone guard word from
/(never|forbidden|not in|assertNotIn|does not appear|is not a surface|
blocklists?)/i — guard assertions, blocklists and doctrine notes are legitimate.
A guard word that only appears inside the prohibited URL or value (a path
segment, query value, subdomain or identifier) does not exempt it.
Canonical surfaces are a-11-oy.com (product) and a11oy.net (proof).

This is the independently reviewed structured candidate (round 2 review, candidate
SHA-256 1091562d…), extracted from the workflow heredoc into a checked-in, unit-
tested module so the negative cases have regression coverage. It uses ripgrep's
structured JSON so a newline-containing filename cannot split the file list, applies
the exemption to source CONTENT only (never a path), and FAILS CLOSED (exit 2) on any
scanner/tool error — a timeout or missing tool is never a silent pass.

Scope is regular files recorded in the Git index, including hidden and ignored
tracked files. Untracked outputs, Git metadata, symlinks and submodule contents
are not scanned. Ignore files and local ripgrep configuration cannot hide a
tracked source file. No extension exclusion is applied.

Exit codes: 0 = clean, 1 = violations found, 2 = scan could not complete.
Keep in sync with alignment/templates/workflows/forbidden-domain.yml.
"""
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

DOMAIN = r"(?<!-)a11oy\.com"
EXEMPTION = r"never|forbidden|not in|assertNotIn|does not appear|is not a surface|blocklists?"
# A guard word only counts as a standalone word (no adjacent letter or digit).
GUARD = r"(?<![A-Za-z0-9])(?:" + EXEMPTION + r")(?![A-Za-z0-9])"
PROHIBITED_HOST = re.compile(DOMAIN.encode())
REFERENCE_TOKEN = re.compile(rb"[^\s\"'`()\[\]{}<>,;]+")
RG = "rg"   # module-level so tests can point it at a missing binary (fail-closed path)
COMMAND_TIMEOUT_SECONDS = 30


def fail(message: str):
    print(f"::error::Forbidden-domain gate could not complete: {message}", file=sys.stderr)
    raise SystemExit(2)


def rg(arguments, source=None, *, cwd=None):
    try:
        result = subprocess.run(
            [RG, "--no-config", *arguments], input=source, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, cwd=cwd,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"ripgrep could not complete ({type(error).__name__})")
    if result.returncode not in (0, 1):
        # Never relay raw stderr: filenames can contain workflow log commands.
        fail(f"ripgrep exited with status {result.returncode}")
    return result


def raw(field):
    """Decode a ripgrep JSON text/bytes field to raw bytes (handles non-UTF-8)."""
    if not isinstance(field, dict) or len(field) != 1:
        raise ValueError("invalid ripgrep text/bytes field")
    if isinstance(field.get("text"), str):
        return field["text"].encode("utf-8")
    if isinstance(field.get("bytes"), str):
        return base64.b64decode(field["bytes"], validate=True)
    raise ValueError("missing ripgrep text/bytes value")


def tracked_sources(root):
    """Enumerate the index with NUL framing; never use ignore rules as authority."""
    try:
        directory = Path(root).resolve(strict=True)
        result = subprocess.run(
            ["git", "-C", os.fspath(directory), "ls-files", "--stage", "-z", "--", "."],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("Git source enumeration could not run")
    if result.returncode != 0 or (result.stdout and not result.stdout.endswith(b"\0")):
        fail("Git source enumeration did not complete")
    paths, seen = [], set()
    try:
        for record in result.stdout.split(b"\0")[:-1]:
            metadata, path = record.split(b"\t", 1)
            mode, _object_id, stage = metadata.split()
            if stage != b"0" or not path or path in seen:
                raise ValueError("unmerged or duplicate index entry")
            seen.add(path)
            if mode in (b"120000", b"160000"):
                continue  # Preserve the no-follow and no-submodule scope.
            parts = path.split(b"/")
            if mode not in (b"100644", b"100755") or any(
                part in (b"", b".", b"..", b".git") for part in parts
            ):
                raise ValueError("unsupported tracked path")
            current = directory
            for index, part in enumerate(parts):
                current = current / os.fsdecode(part)
                observed = current.lstat().st_mode
                expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
                if not expected(observed):
                    raise ValueError("tracked path type changed")
            paths.append(path)
    except (OSError, ValueError, TypeError):
        fail("tracked source paths are missing, unresolved or changed")
    return directory, paths


def batch_matches(scan, expected_paths):
    """Parse one explicit tracked-file batch; inconsistent results fail closed."""
    matches = []
    summary = None
    try:
        for record in scan.stdout.splitlines():
            event = json.loads(record)
            kind, data = event["type"], event["data"]
            if summary is not None or not isinstance(data, dict):
                raise ValueError("invalid or trailing ripgrep record")
            if kind == "match":
                path, line = raw(data["path"]), raw(data["lines"])
                if path not in expected_paths:
                    raise ValueError("result outside tracked source scope")
                number = data["line_number"]
                if type(number) is not int or number < 1:
                    raise ValueError("invalid source line number")
                if not line or b"\n" in line.removesuffix(b"\n"):
                    raise ValueError("expected exactly one source line")
                matches.append((path, number, line))
            elif kind == "summary":
                summary = data["stats"]["matched_lines"]
                if type(summary) is not int or summary < 0:
                    raise ValueError("invalid ripgrep summary")
            elif kind not in ("begin", "end"):
                raise ValueError("unexpected ripgrep record type")
        if summary != len(matches) or (scan.returncode == 0) != bool(matches):
            raise ValueError("incomplete or inconsistent ripgrep results")
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        fail(f"invalid ripgrep JSON ({error})")
    return matches


def collect_matches(root="."):
    """Scan only tracked regular files, independently of every ignore mechanism."""
    directory, paths = tracked_sources(root)
    # An empty repository must not conceal a missing scanner dependency.
    if rg(["--version"]).returncode != 0:
        fail("ripgrep version check did not complete")
    matches, batch, size = [], [], 0

    def collect(values):
        # A tracked file named '-' must never be interpreted as stdin.
        arguments = [b"./" + value for value in values]
        scan = rg(["--json", "--hidden", "--no-ignore", "-P", DOMAIN,
                   "--glob", "!.git", "--", *arguments], cwd=directory)
        return batch_matches(scan, set(arguments))

    for path in paths:
        if batch and (len(batch) >= 128 or size + len(path) + 1 > 16384):
            matches.extend(collect(batch))
            batch, size = [], 0
        batch.append(path)
        size += len(path) + 1
    if batch:
        matches.extend(collect(batch))
    return matches


def outside_forbidden_references(line: bytes) -> bytes:
    """Blank every token of the source line that contains the prohibited host.

    A token is a run of bytes not separated by whitespace, quotes, backticks,
    brackets, braces, angle brackets, commas or semicolons, so a URL's scheme,
    host, port, path, query and fragment travel together. A guard word that occurs
    only inside the prohibited reference itself — a /blocklist path segment, a
    never.<host> subdomain or a ?mode=forbidden query value on the prohibited host —
    is therefore removed before the guard check and can never exempt that same
    reference."""
    return REFERENCE_TOKEN.sub(
        lambda token: b" " * len(token.group(0))
        if PROHIBITED_HOST.search(token.group(0)) else token.group(0),
        line,
    )


def filter_violations(matches):
    """Keep only matches whose SOURCE LINE is not a guard/prohibition context.

    The exemption runs over source content only (a filename can never grant it),
    and only over the part of the line OUTSIDE the prohibited reference. Guard
    words must stand alone as words, so an identifier or path segment that merely
    contains one (forbiddenFruit, /blocklist) is not a guard context. This is a
    lexical gate: a line that deliberately splits the host across string pieces, or
    that mixes a genuine guard with a separate live call, is outside what it can judge."""
    violations = []
    for path, number, line in matches:
        guard = rg(["-P", "-i", "--", GUARD], source=outside_forbidden_references(line))
        if guard.returncode == 1:   # no standalone guard word outside the reference
            violations.append((path, number, line))
    return violations


def scan_root(root="."):
    """Return the list of violations (possibly empty). Raises SystemExit(2) if the
    scan cannot complete. Used by both main() and the regression tests."""
    return filter_violations(collect_matches(root))


def main(root="."):
    violations = scan_root(root)
    if violations:
        print("::error::Forbidden domain references found (release-blocking CRITICAL).")
        print("::error::Replace with a-11-oy.com or remove; guard contexts must say so on the same line.")
        for path, number, line in violations:
            # Escape filenames/source so neither can inject workflow log commands.
            print(json.dumps({
                "path": path.decode("utf-8", "backslashreplace"),
                "line": number,
                "source": line.decode("utf-8", "backslashreplace").removesuffix("\n"),
            }))
        raise SystemExit(1)
    print("OK: no forbidden domain references outside guard contexts.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
