#!/usr/bin/env python3
"""Release-blocking CRITICAL forbidden-domain scanner for the szl-holdings estate.

Rule: every occurrence of

    (?<!-)a11oy\\.com          (matched case-insensitively: DNS names ignore case)

in a tracked source is a violation UNLESS that occurrence itself sits in an explicit
prohibition/guard context. Canonical surfaces are a-11-oy.com (product) and a11oy.net
(proof). The guard vocabulary is unchanged:
/(never|forbidden|not in|assertNotIn|does not appear|is not a surface|blocklists?)/i.

Exemption is judged per occurrence, never per line (see "Per-occurrence guard
judgement" below). An occurrence is covered only by
  - PROSE: a prose line, HTML text, comment, or a string that names the bare host,
    whose own text holds a standalone guard phrase outside the host's token;
  - KEYED: literal data bound directly to a guard-named key or constant
    (BLOCKLIST = [...], "never": "...", FORBIDDEN_HOST = "..."), outside any call;
  - ABSENT: assertNotIn("<host>", ...) or "<host>" not in ...
A guard word in an identifier (forbidden_url), in another argument of a call, inside
the prohibited URL, or elsewhere on a line that also makes a live reference covers
nothing. Locators (scheme, //, path, port, query) in code strings and link targets
are never exempted by prose.

Scope is regular files recorded in the Git index, including hidden and ignored
tracked files. Untracked outputs, Git metadata, symlinks and submodule contents
are not scanned. Ignore files and local ripgrep configuration cannot hide a
tracked source file. No extension exclusion is applied; the extension only selects
how comments and strings are recognised, and unknown types are read as code.

Limits (lexical gate, not a parser or data-flow analysis): a host split across
string pieces, a guard-named constant later passed to a call, and inline <script>
content inside HTML text are outside what it can judge.

Ripgrep's structured JSON keeps newline-containing filenames intact; the exemption
reads source CONTENT only (never a path); every matched file is re-read and a line
that changed meanwhile, like any scanner/tool error, FAILS CLOSED (exit 2).

Exit codes: 0 = clean, 1 = violations found, 2 = scan could not complete.
"""
import base64
import bisect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

DOMAIN = r"(?<!-)a11oy\.com"
EXEMPTION = r"never|forbidden|not in|assertNotIn|does not appear|is not a surface|blocklists?"
# A guard phrase only counts standing alone: no adjacent letter, digit, "_" or "$",
# so an identifier such as forbidden_url or neverHost never supplies one.
GUARD = r"(?<![A-Za-z0-9_$])(?:" + EXEMPTION + r")(?![A-Za-z0-9_$])"
PROHIBITED_HOST = re.compile(DOMAIN.encode(), re.IGNORECASE)   # DNS names ignore case
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
        scan = rg(["--json", "--hidden", "--no-ignore", "--ignore-case", "-P", DOMAIN,
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
    return directory, matches


# --------------------------------------------------------------------------------
# Per-occurrence guard judgement
#
# A matched line passes only when EVERY occurrence of the prohibited host on it is
# covered by one explicit prohibition shape. A guard word elsewhere on the line, in an
# identifier, or in another argument never covers an occurrence.
#
#   PROSE   The occurrence names the BARE host in prose: a prose-file line, a line's
#           HTML text (attribute values blanked), one attribute value, a comment, or a
#           string literal. That same prose unit, on the same line, holds a standalone
#           guard phrase outside every token that carries the host. A locator (scheme,
#           //, path, port, query, fragment) or link target is never prose-exempt.
#   KEYED   The occurrence is literal data bound directly to a key or assignment target
#           with a guard component (never, forbidden, blocklist, blocklists) split on
#           "_", "-" and ".", alone or in a literals-only collection. The key must be on
#           the occurrence's own line and outside every call's parentheses, and nothing
#           may chain onto the value.
#   ABSENT  The string literal is the first argument of assertNotIn( or is followed by
#           "not in": an assertion that the host is absent.
#
# The lexer below is deliberately small, not a parser. What it cannot place — an
# unbalanced bracket, an unknown file type, an unterminated string — is read the
# stricter way: as code, with no keyed exemption.
# --------------------------------------------------------------------------------

WHITESPACE = b" \t\r\n\f\v"
# In prose, quotes, backticks and tag brackets also end a word, so a doc's
# `assertNotIn("<host>", x)` or HTML `<td>never</td>` keeps its guard word. A locator
# (URL) is still masked as its whole whitespace-delimited token, so URL punctuation
# (; , ( ? = < >) inside it never exposes a guard word.
PROSE_STOPS = WHITESPACE + b"\"'`<>"
GUARD_PHRASE = re.compile(GUARD.encode(), re.IGNORECASE)
GUARD_KEY_PARTS = frozenset((b"never", b"forbidden", b"blocklist", b"blocklists"))
# A guard phrase next to path, query or assignment punctuation is not prose.
NOT_PROSE_BEFORE = frozenset(b"/=?&%\\")
NOT_PROSE_AFTER = frozenset(b"/=?&%\\")
LOCATOR_PREFIX = re.compile(rb"(?:\\?/|%2[Ff]){2}")
LINK_TARGET = re.compile(rb"\]\(|(?:href|src|srcset|action|url)\s*[=(]|<[A-Za-z][A-Za-z0-9+.\-]*:", re.IGNORECASE)
LINK_DEFINITION = re.compile(rb"[ \t]{0,3}\[[^\]\n]*\]:")
FENCE_OPEN = re.compile(rb"[ \t]{0,3}(`{3,}|~{3,})[ \t]*\{?\.?([A-Za-z0-9_+\-]*)")
ASSERT_NOT_IN_CALL = re.compile(rb"(?<![A-Za-z0-9_$])assertNotIn[ \t]*\([ \t\r\n]*\Z")
NOT_IN_AFTER = re.compile(rb"[ \t]+not[ \t]+in(?![A-Za-z0-9_$])")
INLINE_BINDING = re.compile(rb"([A-Za-z_][A-Za-z0-9_.\-]*)=")
NAME_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$.-")
WORD_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
# Words that may introduce a binding (`export const NEVER = ...`, `assert X == ...`).
BINDING_PREFIXES = frozenset((
    b"const", b"let", b"var", b"export", b"readonly", b"local", b"declare", b"final",
    b"static", b"public", b"private", b"protected", b"val", b"assert", b"if", b"elif",
    b"and", b"or", b"not", b"return", b"while",
))
CHAINING = frozenset(b".([+*/%|&?<>=!^~")
CLOSER_FOR = {ord("["): ord("]"), ord("("): ord(")"), ord("{"): ord("}")}
OPENER_FOR = {closer: opener for opener, closer in CLOSER_FOR.items()}

# Line comment rules: None = anywhere outside a string; "space" = at the start of the
# text or after whitespace (shell/YAML); "scheme" = not directly after ':' (keeps
# https:// out of a comment). multiline: (open, close, backslash escapes).
# regex: recognise JS regex literals. brackets=False: nesting is not trusted (JSX
# text may hold any bracket), so a keyed exemption is never available there.
FAMILIES = {
    "python": dict(quotes=b"\"'", escapes=b"\"'",
                   multiline=((b'"""', b'"""', True), (b"'''", b"'''", True)),
                   line=((b"#", None),), block=()),
    "hash": dict(quotes=b"\"'", escapes=b'"', multiline=(), line=((b"#", "space"),), block=()),
    "script": dict(quotes=b"\"'", escapes=b"\"'", multiline=((b"`", b"`", True),),
                   line=((b"//", "scheme"),), block=((b"/*", b"*/"),), regex=True),
    "jsx": dict(quotes=b"\"'", escapes=b"\"'", multiline=((b"`", b"`", True),),
                line=((b"//", "scheme"),), block=((b"/*", b"*/"),), regex=True, brackets=False),
    "c": dict(quotes=b"\"'", escapes=b"\"'", multiline=(),
              line=((b"//", "scheme"),), block=((b"/*", b"*/"),)),
    "css": dict(quotes=b"\"'", escapes=b"\"'", multiline=(), line=(), block=((b"/*", b"*/"),)),
    "dash": dict(quotes=b'"', escapes=b'"', multiline=(),
                 line=((b"--", None),), block=((b"/-", b"-/"), (b"{-", b"-}"), (b"/*", b"*/"))),
    "lua": dict(quotes=b"\"'", escapes=b"\"'", multiline=((b"[[", b"]]", False),),
                line=((b"--", None),), block=((b"--[[", b"]]"),)),
    "data": dict(quotes=b'"', escapes=b'"', multiline=(), line=(), block=()),
    # HTML/XML: text outside attribute values and comments is prose.
    "html": dict(quotes=b'"', escapes=b"", multiline=(),
                 line=(), block=((b"<!--", b"-->"),), structured=False),
}
for _spec in FAMILIES.values():
    _spec.setdefault("structured", True)
    _spec.setdefault("regex", False)
    _spec.setdefault("brackets", True)
    _starts = set(_spec["quotes"])
    if _spec["regex"]:
        _starts.add(ord("/"))
    for _marker in [*(m for m, _, _ in _spec["multiline"]), *(m for m, _ in _spec["line"]),
                    *(o for o, _ in _spec["block"])]:
        _starts.add(_marker[0])
    _spec["interesting"] = re.compile(b"[" + b"".join(re.escape(bytes((b,))) for b in sorted(_starts)) + b"]") if _starts else None

EXTENSIONS = {
    ".py": "python", ".pyi": "python",
    ".js": "script", ".mjs": "script", ".cjs": "script", ".ts": "script", ".mts": "script",
    ".cts": "script", ".go": "script", ".jsx": "jsx", ".tsx": "jsx",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".hpp": "c", ".java": "c", ".rs": "c",
    ".swift": "c", ".kt": "c", ".kts": "c", ".scala": "c", ".cs": "c", ".php": "c", ".dart": "c",
    ".css": "css", ".scss": "css", ".less": "css",
    ".sql": "dash", ".hs": "dash", ".lean": "dash", ".lua": "lua",
    ".json": "data", ".jsonl": "data", ".ndjson": "data", ".geojson": "data", ".ipynb": "data",
    ".html": "html", ".htm": "html", ".xhtml": "html", ".xml": "html", ".svg": "html",
    ".md": "prose", ".markdown": "prose", ".txt": "prose", ".rst": "prose", ".adoc": "prose",
}
FENCE_LANGUAGES = {
    b"python": "python", b"py": "python", b"js": "script", b"javascript": "script",
    b"ts": "script", b"typescript": "script", b"jsx": "jsx", b"tsx": "jsx",
    b"json": "data", b"html": "html", b"xml": "html", b"css": "css", b"sql": "dash",
    b"lean": "dash", b"lua": "lua",
}
# A '/' after one of these (or a keyword) starts a JS regex literal, not a division.
REGEX_PRECEDERS = frozenset(b"(,=:[!&|?{};+-*%<>~^")
REGEX_KEYWORDS = frozenset((
    b"return", b"typeof", b"void", b"delete", b"in", b"of", b"new", b"instanceof",
    b"case", b"do", b"else", b"throw", b"yield", b"await",
))


def family_for(path: bytes) -> str:
    """Unknown file types are read with shell/YAML rules (all code, # comments)."""
    name = path.rsplit(b"/", 1)[-1].lower()
    dot = name.rfind(b".")
    return EXTENSIONS.get(os.fsdecode(name[dot:]) if dot > 0 else "", "hash")


def token_bounds(data, low, high, start, stop, stops=WHITESPACE):
    """The token around [start, stop) within [low, high), delimited by `stops`."""
    while start > low and data[start - 1] not in stops:
        start -= 1
    while stop < high and data[stop] not in stops:
        stop += 1
    return start, stop


def is_locator(data, token_start, token_end, start, stop):
    """A host occurrence used as a URL: scheme or //, or a path, port, query,
    fragment or userinfo right after the host."""
    after = data[stop:token_end]
    return bool(LOCATOR_PREFIX.search(data, token_start, start)) or (
        after[:1] in (b"/", b"?", b"#", b"@", b"\\", b"%")
        or re.match(rb":[0-9]", after) is not None
    )


def advance(stack, chunk):
    """Replay brackets in code bytes; an unbalanced closer makes the stack unknown."""
    if stack is None:
        return None
    stack = list(stack)
    for byte in chunk:
        if byte in CLOSER_FOR:
            stack.append(byte)
        elif byte in OPENER_FOR:
            if not stack or stack.pop() != OPENER_FOR[byte]:
                return None
    return stack


def scan_string(data, index, end, delimiter, escapes, multiline):
    """Return (end of literal, end of its content). A single-line literal that is
    not closed stops at the line break."""
    while index < end:
        if escapes and data[index] == 0x5C:
            index += 2
            continue
        if data.startswith(delimiter, index):
            return index + len(delimiter), index
        if not multiline and data[index] == 0x0A:
            return index, index
        index += 1
    return end, end


def scan_regex(data, index, begin, end):
    """If the '/' at `index` starts a JS regex literal, return (its end, ambiguous),
    else None. At a line start a '/' may also continue a division from the previous
    line, so that reading is flagged ambiguous."""
    previous = index
    while previous > begin and data[previous - 1] in b" \t":
        previous -= 1
    ambiguous = previous > begin and data[previous - 1] == 0x0A
    if previous > begin and data[previous - 1] not in REGEX_PRECEDERS and not ambiguous:
        word_end = previous
        while previous > begin and data[previous - 1] in WORD_BYTES:
            previous -= 1
        if data[previous:word_end] not in REGEX_KEYWORDS:
            return None
    cursor, in_class = index + 1, False
    while cursor < end and data[cursor] != 0x0A:
        byte = data[cursor]
        if byte == 0x5C:
            cursor += 2
            continue
        if in_class:
            in_class = byte != ord("]")
        elif byte == ord("["):
            in_class = True
        elif byte == ord("/"):
            cursor += 1
            while cursor < end and data[cursor] in WORD_BYTES:
                cursor += 1
            return cursor, ambiguous
        cursor += 1
    return None


class Segment:
    __slots__ = ("start", "end", "kind", "inner_start", "inner_end", "stack", "structured")

    def __init__(self, start, end, kind, inner_start, inner_end, stack, structured):
        self.start, self.end, self.kind = start, end, kind
        self.inner_start, self.inner_end = inner_start, inner_end
        self.stack, self.structured = stack, structured


class Source:
    """One tracked file split into code / literal / comment / prose segments."""

    def __init__(self, data: bytes, family: str):
        self.data = data
        self.segments = []
        if family == "prose":
            self._lex_prose()
        else:
            self._lex(0, len(data), family)
        self.starts = [segment.start for segment in self.segments]
        self.line_starts = None

    # -- lexing -------------------------------------------------------------------
    def _add(self, *fields):
        if fields[1] > fields[0]:
            self.segments.append(Segment(*fields))

    def _lex(self, begin, end, family):
        spec, data = FAMILIES[family], self.data
        structured = spec["structured"]
        stack = [] if structured and spec["brackets"] else None
        code_kind = "code" if structured else "text"
        index = code_start = begin

        def flush(upto):
            nonlocal stack
            self._add(code_start, upto, code_kind, code_start, upto,
                      None if stack is None else tuple(stack), structured)
            stack = advance(stack, data[code_start:upto])

        while index < end:
            found = spec["interesting"].search(data, index, end) if spec["interesting"] else None
            if found is None:
                break
            index = found.start()
            segment = None
            for opener, closer in spec["block"]:
                if data.startswith(opener, index):
                    close = data.find(closer, index + len(opener), end)
                    stop = end if close < 0 else close + len(closer)
                    segment = ("comment", stop, index + len(opener), end if close < 0 else close)
                    break
            if segment is None:
                for marker, rule in spec["line"]:
                    if data.startswith(marker, index) and (
                        rule is None or index == begin
                        or (rule == "space" and data[index - 1] in WHITESPACE)
                        or (rule == "scheme" and data[index - 1] != ord(":"))
                    ):
                        newline = data.find(b"\n", index, end)
                        stop = end if newline < 0 else newline
                        segment = ("comment", stop, index + len(marker), stop)
                        break
            if segment is None:
                for opener, closer, escapes in spec["multiline"]:
                    if data.startswith(opener, index):
                        stop, inner = scan_string(data, index + len(opener), end, closer, escapes, True)
                        segment = ("literal", stop, index + len(opener), inner)
                        break
            poison = False
            if segment is None and spec["regex"] and data[index] == ord("/"):
                regex = scan_regex(data, index, begin, end)
                if regex is not None:
                    segment, poison = ("literal", regex[0], index + 1, regex[0] - 1), regex[1]
            if segment is None and data[index] in spec["quotes"]:
                quote = data[index:index + 1]
                stop, inner = scan_string(data, index + 1, end, quote, data[index] in spec["escapes"], False)
                segment = ("literal", stop, index + 1, inner)
            if segment is None:
                index += 1
                continue
            flush(index)
            kind, stop, inner_start, inner_end = segment
            self._add(index, stop, kind, inner_start, inner_end,
                      None if stack is None else tuple(stack), structured)
            if poison:   # either reading could hide a bracket: stop trusting nesting
                stack = None
            index = code_start = max(stop, index + 1)
        flush(end)

    def _lex_prose(self):
        """Prose lines are prose; fenced code blocks are lexed as code."""
        data, index, fence = self.data, 0, None
        while index < len(data):
            newline = data.find(b"\n", index)
            stop = len(data) if newline < 0 else newline
            following = len(data) if newline < 0 else newline + 1
            line = data[index:stop].rstrip(b"\r")
            if fence is None:
                opened = FENCE_OPEN.match(line)
                if opened:
                    marker = opened.group(1)
                    fence = (marker[:1], len(marker), following,
                             FENCE_LANGUAGES.get(opened.group(2).lower(), "hash"))
                self._add(index, stop, "prose", index, stop, None, False)
            elif re.fullmatch(rb"[ \t]{0,3}" + re.escape(fence[0]) + rb"{%d,}[ \t]*" % fence[1], line):
                self._lex(fence[2], index, fence[3])
                self._add(index, stop, "prose", index, stop, None, False)
                fence = None
            index = following
        if fence is not None:
            self._lex(fence[2], len(data), fence[3])

    # -- navigation ---------------------------------------------------------------
    def segment_at(self, position):
        index = bisect.bisect_right(self.starts, position) - 1
        if index >= 0 and self.segments[index].end > position:
            return self.segments[index]
        return None

    def stack_at(self, position):
        segment = self.segment_at(position)
        if segment is None or segment.stack is None:
            return None
        if segment.kind != "code":
            return segment.stack
        return advance(segment.stack, self.data[segment.start:position])

    def literal_ending_at(self, position):
        segment = self.segment_at(position - 1) if position > 0 else None
        return segment if segment and segment.kind == "literal" and segment.end == position else None

    def literal_starting_at(self, position):
        segment = self.segment_at(position)
        return segment if segment and segment.kind == "literal" and segment.start == position else None

    def skip_back(self, position):
        while position > 0:
            if self.data[position - 1] in WHITESPACE:
                position -= 1
                continue
            segment = self.segment_at(position - 1)
            if segment is not None and segment.kind == "comment":
                position = segment.start
                continue
            break
        return position

    def skip_forward(self, position):
        while position < len(self.data):
            if self.data[position] in WHITESPACE:
                position += 1
                continue
            segment = self.segment_at(position)
            if segment is not None and segment.kind == "comment" and segment.start == position:
                position = segment.end
                continue
            break
        return position

    # -- judgement ----------------------------------------------------------------
    def judge(self, number, line):
        """True when every prohibited occurrence on this matched line is covered."""
        if self.line_starts is None:
            self.line_starts = [0] + [m.end() for m in re.finditer(b"\n", self.data)]
        if number > len(self.line_starts):
            fail("a matched source line is missing on re-read")
        line_start = self.line_starts[number - 1]
        newline = self.data.find(b"\n", line_start)
        after = len(self.data) if newline < 0 else newline + 1
        if self.data[line_start:after] != line:
            fail("a matched source line changed during the scan")
        line_end = after if newline < 0 else newline
        if line_end > line_start and self.data[line_end - 1] == 0x0D:
            line_end -= 1
        occurrences = list(PROHIBITED_HOST.finditer(self.data, line_start, line_end))
        if not occurrences:
            fail("ripgrep and the guard disagree about a match")
        return all(self.covered(m.start(), m.end(), line_start, line_end) for m in occurrences)

    def covered(self, start, stop, line_start, line_end):
        segment = self.segment_at(start)
        if segment is None or stop > segment.end:
            return False
        low = max(segment.inner_start, line_start)
        high = min(segment.inner_end, line_end)
        if segment.kind in ("code", "literal") and self.structural(segment, start, stop, line_start, line_end):
            return True
        if segment.kind == "code":
            return False
        if segment.kind == "prose" and self.prose_line_structural(start, stop, line_start, line_end):
            return True
        if segment.kind == "text":
            text, offset = self.text_unit(line_start, line_end), line_start
        else:
            text, offset = self.data[low:high], low
        # Prose may only exempt the bare host name, never a URL to it.
        token_start, token_end = token_bounds(text, 0, len(text), start - offset, stop - offset)
        if is_locator(text, token_start, token_end, start - offset, stop - offset):
            return False
        return self.prose_guard(text, offset, start, stop, line_start)

    def structural(self, segment, start, stop, line_start, line_end):
        """KEYED or ABSENT shape for an occurrence in code or in a string literal."""
        if segment.kind == "code":
            return self.keyed_bare(segment, start, stop, line_start, line_end)
        return segment.kind == "literal" and segment.structured and (
            self.keyed_literal(segment, line_start) or self.asserted_absent(segment)
        )

    def prose_line_structural(self, start, stop, line_start, line_end):
        """A prose-file line written as code (a doc quoting `BLOCKLIST = [...]`) may
        use the KEYED/ABSENT shapes, judged as a one-line shell/YAML-style source."""
        line = Source(self.data[line_start:line_end], "hash")
        relative = start - line_start
        segment = line.segment_at(relative)
        if segment is None or stop - line_start > segment.end:
            return False
        return line.structural(segment, relative, stop - line_start, 0, line_end - line_start)

    def text_unit(self, line_start, line_end):
        """HTML text of one line, with attribute values and comments blanked out."""
        unit = bytearray(self.data[line_start:line_end])
        index = max(0, bisect.bisect_right(self.starts, line_start) - 1)
        while index < len(self.segments) and self.segments[index].start < line_end:
            segment = self.segments[index]
            if segment.kind != "text":
                low, high = max(segment.start, line_start), min(segment.end, line_end)
                if high > low:
                    unit[low - line_start:high - line_start] = b" " * (high - low)
            index += 1
        return bytes(unit)

    def prose_guard(self, text, offset, start, stop, line_start):
        """`text` is the prose unit, starting at absolute position `offset`."""
        relative = start - offset
        token_start, _ = token_bounds(text, 0, len(text), relative, stop - offset)
        if LINK_TARGET.search(text, token_start, relative):
            return False
        if LINK_DEFINITION.match(self.data, line_start, start) is not None:
            return False
        unit = bytearray(text)
        for host in PROHIBITED_HOST.finditer(text):
            first, last = token_bounds(text, 0, len(text), host.start(), host.end())
            if not is_locator(text, first, last, host.start(), host.end()):
                first, last = token_bounds(text, 0, len(text), host.start(), host.end(), PROSE_STOPS)
            unit[first:last] = b" " * (last - first)
        unit = bytes(unit)
        for phrase in GUARD_PHRASE.finditer(unit):
            first, last = token_bounds(unit, 0, len(unit), phrase.start(), phrase.end(), PROSE_STOPS)
            before = unit[phrase.start() - 1] if phrase.start() else 0x20
            after = unit[phrase.end()] if phrase.end() < len(unit) else 0x20
            if b"://" in unit[first:last] or before in NOT_PROSE_BEFORE or after in NOT_PROSE_AFTER:
                continue
            return True
        return False

    def keyed_literal(self, segment, line_start):
        data = self.data
        position = self.skip_back(segment.start)
        crossed = False
        while position > 0 and data[position - 1] == ord(","):
            previous = self.literal_ending_at(self.skip_back(position - 1))
            if previous is None:
                return False
            position, crossed = self.skip_back(previous.start), True
        opener = None
        if position > 0 and data[position - 1] in CLOSER_FOR:
            opener = data[position - 1]
            position = self.skip_back(position - 1)
        elif crossed:
            return False
        cursor = segment.end
        if opener is not None:
            closer = CLOSER_FOR[opener]
            cursor = self.skip_forward(cursor)
            while cursor < len(data) and data[cursor] == ord(","):
                cursor = self.skip_forward(cursor + 1)
                if cursor < len(data) and data[cursor] == closer:
                    break
                following = self.literal_starting_at(cursor)
                if following is None:
                    return False
                cursor = self.skip_forward(following.end)
            if cursor >= len(data) or data[cursor] != closer:
                return False
            cursor += 1
        cursor = self.skip_forward(cursor)
        if cursor < len(data) and data[cursor] in CHAINING:
            return False
        return self.guard_binding(position, line_start)

    def keyed_bare(self, segment, start, stop, line_start, line_end):
        """An unquoted value (YAML/INI/shell) bound to a guard-named key, ending its line."""
        data = self.data
        low, high = max(segment.start, line_start), min(segment.end, line_end)
        token_start, token_end = token_bounds(data, low, high, start, stop)
        rest = token_end
        while rest < line_end and data[rest] in b" \t":
            rest += 1
        if rest < line_end:
            following = self.segment_at(rest)
            if following is None or following.kind != "comment" or following.start != rest:
                return False
        inline = INLINE_BINDING.match(data, token_start, start)
        if inline is not None:
            return self.guard_name(inline.group(1), token_start, line_start)
        position = token_start
        while position > line_start and data[position - 1] in b" \t":
            position -= 1
        return self.guard_binding(position, line_start)

    def guard_binding(self, position, line_start):
        """`position` sits just after an operator; accept `key:`, `key =` or `key ==`
        whose key is a guard name at the start of a statement or entry."""
        data = self.data
        if position >= 1 and data[position - 1] == ord(":"):
            if position >= 2 and data[position - 2] == ord(":"):
                return False
            key_end = position - 1
        elif position >= 1 and data[position - 1] == ord("="):
            if position >= 2 and data[position - 2] == ord("="):
                if position >= 3 and data[position - 3] in b"=!<>":
                    return False
                key_end = position - 2
            elif position >= 2 and data[position - 2] in b"!<>+-*/%&|^~:?.@":
                return False
            else:
                key_end = position - 1
        else:
            return False
        while key_end > 0 and data[key_end - 1] in b" \t":
            key_end -= 1
        quoted = self.literal_ending_at(key_end)
        if quoted is not None:
            return self.guard_name(data[quoted.inner_start:quoted.inner_end], quoted.start, line_start)
        key_start = key_end
        while key_start > 0 and data[key_start - 1] in NAME_BYTES:
            key_start -= 1
        name = data[key_start:key_end]
        if not name or not (name[:1].isalpha() or name[:1] in (b"_", b"$")):
            return False
        return self.guard_name(name, key_start, line_start)

    def guard_name(self, name, key_start, line_start):
        # The guard must still be stated on the occurrence's own line.
        if key_start < line_start or PROHIBITED_HOST.search(name):
            return False
        if not GUARD_KEY_PARTS.intersection(re.split(rb"[_.\-]+", name.lower())):
            return False
        if not self.entry_start(key_start):
            return False
        stack = self.stack_at(key_start)
        return stack is not None and ord("(") not in stack

    def entry_start(self, position):
        data = self.data
        for _ in range(4):
            while position > 0 and data[position - 1] in b" \t":
                position -= 1
            if position == 0 or data[position - 1] in b"\n{[(,;":
                return True
            if data[position - 1] == ord("-"):        # YAML list item `- never: ...`
                position -= 1
                continue
            word_end = position
            while position > 0 and data[position - 1] in WORD_BYTES:
                position -= 1
            if data[position:word_end] not in BINDING_PREFIXES:
                return False
        return False

    def asserted_absent(self, segment):
        data = self.data
        call = ASSERT_NOT_IN_CALL.search(data, max(0, segment.start - 64), segment.start)
        if call is not None:
            opener = data.rfind(b"(", call.start(), segment.start)
            owner = self.segment_at(opener)
            if owner is not None and owner.kind == "code":
                return True
        following = NOT_IN_AFTER.match(data, segment.end)
        if following is not None:
            owner = self.segment_at(segment.end)
            return owner is not None and owner.kind == "code"
        return False


def load_source(directory, path):
    """Re-read one tracked regular file without following a final symlink."""
    try:
        descriptor = os.open(os.path.join(os.fsencode(directory), path),
                             os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not a regular file")
            data = stream.read()
    except (OSError, ValueError):
        fail("a matched tracked source could not be re-read")
    return Source(data, family_for(path))


def filter_violations(matches, directory):
    """Keep matches with any prohibited occurrence not covered by a guard shape.

    The judgement reads source CONTENT only — a filename never grants an exemption —
    and re-reads each matched file to see multi-line strings, comments and brackets.
    A line that changed between the scan and the re-read fails closed."""
    violations, current, source = [], None, None
    for path, number, line in matches:
        if path != current:
            current, source = path, load_source(directory, path)
        if not source.judge(number, line):
            violations.append((path, number, line))
    return violations


def scan_root(root="."):
    """Return the list of violations (possibly empty). Raises SystemExit(2) if the
    scan cannot complete. Used by both main() and the regression tests."""
    directory, matches = collect_matches(root)
    try:
        return filter_violations(matches, directory)
    except Exception as error:   # a guard defect must never read as a clean or dirty scan
        fail(f"guard judgement could not complete ({type(error).__name__})")


def main(root="."):
    violations = scan_root(root)
    if violations:
        print("::error::Forbidden domain references found (release-blocking CRITICAL).")
        print("::error::Replace with a-11-oy.com or remove; each occurrence needs its own guard shape on its line.")
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
