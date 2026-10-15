#!/usr/bin/env python3
"""Release-blocking CRITICAL forbidden-domain scanner for the szl-holdings estate.

Rule (validated on the live org): a line matching

    (?<!-)a11oy\\.com

is a violation UNLESS the same line is a prohibition/guard context, i.e. it also
matches /(never|forbidden|not in|assertNotIn|does not appear|is not a surface|
blocklist)/i — guard assertions, blocklists and doctrine notes are legitimate.
Canonical surfaces are a-11-oy.com (product) and a11oy.net (proof).

This is the independently reviewed structured candidate (round 2 review, candidate
SHA-256 1091562d…), extracted from the workflow heredoc into a checked-in, unit-
tested module so the negative cases have regression coverage. It uses ripgrep's
structured JSON so a newline-containing filename cannot split the file list, applies
the exemption to source CONTENT only (never a path), and FAILS CLOSED (exit 2) on any
scanner/tool error — a timeout or missing tool is never a silent pass.

Exit codes: 0 = clean, 1 = violations found, 2 = scan could not complete.
Keep in sync with alignment/templates/workflows/forbidden-domain.yml.
"""
import base64
import json
import subprocess
import sys

DOMAIN = r"(?<!-)a11oy\.com"
EXEMPTION = r"never|forbidden|not in|assertNotIn|does not appear|is not a surface|blocklist"
RG = "rg"   # module-level so tests can point it at a missing binary (fail-closed path)


def fail(message: str):
    print(f"::error::Forbidden-domain gate could not complete: {message}", file=sys.stderr)
    raise SystemExit(2)


def rg(arguments, source=None):
    try:
        result = subprocess.run(
            [RG, *arguments], input=source, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
    except OSError as error:
        fail(f"ripgrep could not run ({error})")
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


def collect_matches(root="."):
    """Return [(path_bytes, line_number, line_bytes)] for every line matching DOMAIN,
    parsed from ripgrep's structured JSON (newline-safe). Fails closed on any error."""
    scan = rg(["--json", "--hidden", "-P", DOMAIN, "--glob", "!.git", root])
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


def filter_violations(matches):
    """Keep only matches whose SOURCE LINE is not a guard/prohibition context. The
    exemption runs over the content bytes only (same rg engine + case folding); a
    filename can never grant an exemption."""
    violations = []
    for path, number, line in matches:
        guard = rg(["-i", "--", EXEMPTION], source=line)
        if guard.returncode == 1:   # exemption word NOT present on the content line
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
