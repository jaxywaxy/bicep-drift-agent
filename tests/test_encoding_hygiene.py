"""
Every text file this repo reads or writes must name its encoding.

`Path.read_text()` and `open()` without `encoding=` use the LOCALE's preferred
encoding. On a developer machine that is UTF-8 and everything passes; in a CI
container with `LC_ALL=C` it is US-ASCII, and reading a report whose narrative
contains an em-dash raises UnicodeDecodeError. Verified on Python 3.14:

    LC_ALL=C python -c "import pathlib; pathlib.Path('r.json').read_text()"
    UnicodeDecodeError: 'ascii' codec can't decode byte 0xe2 ...

That is a crash, not mojibake - the report never gets verified at all. (PEP 686
makes UTF-8 the default in 3.15, which will mask this rather than fix the
habit, and this repo does not pin 3.15.)

A grep for this is unreliable - `read_text()` and `read_text(encoding=...)`
differ by a keyword, and mode strings vary - so the check parses the AST.
Found five sites when first written, three of them the report reads that
prompted it.
"""

import ast
import os
import pathlib
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Third-party source vendored for MCP evaluation (gitignored), and virtualenvs.
#: Not ours to fix, and their style is not our invariant.
EXCLUDED_DIRS = ("evaluate", ".venv", "venv", "node_modules", ".git")

#: The test suite itself is exempt. A test that mis-decodes fails loudly and
#: locally, and retrofitting ~120 call sites would bury the signal this guard
#: exists to give. Production code has no such luxury: it fails in CI, on an
#: estate nobody is watching, hours after the change that caused it.
EXCLUDED_DIRS_FOR_TESTS = ("tests",)


def _text_io_without_encoding(node: ast.Call) -> str | None:
    """The call's description if it does text I/O with no encoding, else None."""
    if any(k.arg == "encoding" for k in node.keywords):
        return None
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in ("read_text", "write_text"):
        return f"{func.attr}()"
    if isinstance(func, ast.Name) and func.id == "open":
        mode = ""
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value or ""
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = keyword.value.value or ""
        if "b" not in mode:  # binary has no encoding, correctly
            return f"open(mode={mode or 'r'!r})"
    return None


def _scan(*, include_tests: bool) -> list[str]:
    skip = EXCLUDED_DIRS if include_tests else EXCLUDED_DIRS + EXCLUDED_DIRS_FOR_TESTS
    offenders = []
    for path in sorted(REPO.rglob("*.py")):
        rel = path.relative_to(REPO)
        if rel.parts and rel.parts[0] in skip:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (what := _text_io_without_encoding(node)):
                offenders.append(f"{rel}:{node.lineno} {what}")
    return offenders


class EncodingIsAlwaysExplicitTests(unittest.TestCase):
    def test_no_production_text_io_relies_on_the_locale(self):
        offenders = _scan(include_tests=False)
        self.assertEqual(
            offenders, [],
            "These read or write text without encoding='utf-8', so their behaviour "
            "depends on the CI container's locale:\n  " + "\n  ".join(offenders))

    def test_the_scanner_actually_detects_the_pattern(self):
        """A guard that silently matches nothing is worse than no guard: it
        reports clean forever. Pin that each shape is still recognised."""
        cases = {
            "p.read_text()": "read_text()",
            "p.write_text(s)": "write_text()",
            "open(f)": "open(mode='r')",
            "open(f, 'a')": "open(mode='a')",
            "open(f, mode='w')": "open(mode='w')",
        }
        for source, expected in cases.items():
            with self.subTest(source):
                call = ast.parse(source).body[0].value
                self.assertEqual(_text_io_without_encoding(call), expected)

    def test_the_scanner_does_not_flag_correct_code(self):
        for source in ('p.read_text(encoding="utf-8")',
                       'open(f, "a", encoding="utf-8")',
                       'open(f, "rb")',
                       'open(f, mode="wb")'):
            with self.subTest(source):
                call = ast.parse(source).body[0].value
                self.assertIsNone(_text_io_without_encoding(call))

    def test_the_scan_reaches_real_files(self):
        """If rglob or the exclusion list ever stops matching this repo, the
        production check passes vacuously."""
        self.assertGreater(len(_scan(include_tests=True)), 0,
                           "scanner found nothing at all, including in tests - "
                           "it is no longer reading the repo")


if __name__ == "__main__":
    unittest.main()
