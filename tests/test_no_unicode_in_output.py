"""
Permanent regression guard for the Windows cp1252 UnicodeEncodeError class
of bug that has been rediscovered and fixed by hand several times this
project (scrapers, orchestrator.py, pipeline/process.py, monitoring/
agent_monitor.py, testing/agent_scanner.py, testing/cli.py): printing a
literal emoji or other non-ASCII character crashes on Windows consoles
that default to cp1252, unless something has reconfigured stdout/stderr
to UTF-8 first.

Statically scans every .py file in the repo (via ast, not regex) for
print()/logger.*()/logging.*() calls whose literal string arguments
contain a non-ASCII character - the exact same manual check performed
by hand throughout this session, now enforced automatically so a new
file can't reintroduce it unnoticed.

Known, accepted limitations (not fixable by a static source scan):
- Only catches literal string constants passed directly to the call
  (including f-string literal parts). A non-ASCII character reaching
  print() indirectly - via a variable, a list built elsewhere, or
  scraped data (e.g. a Cyrillic threat title from FSTEC) - is invisible
  to this check. Those are handled at the point of writing (UTF-8 file
  I/O with ensure_ascii=False) rather than by avoiding non-ASCII output
  entirely, since that data is legitimate and shouldn't be mangled.
- Only recognizes `print(...)` and calls on an object named `logger` or
  `logging` (this project's actual convention - see the `logger =
  logging.getLogger(__name__)` lines). It deliberately does NOT flag
  Streamlit's st.info/st.warning/st.error, which render in the browser
  DOM, not the OS console, and are unaffected by this bug class.
"""

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Entry-point scripts that reconfigure sys.stdout/sys.stderr to UTF-8
# before printing (see the reconfigure() calls in each file) and are
# therefore safe despite containing literal non-ASCII in their output -
# add a file here only alongside a corresponding reconfigure() call.
EXEMPT_FILES = {
    "orchestrator.py",
    "pipeline/process.py",
}

EXCLUDE_DIRS = {".venv", ".git", "__pycache__", "node_modules"}

LOGGER_NAMES = {"logger", "logging"}
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}


def _has_nonascii_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return any(ord(c) > 127 for c in node.value)
    if isinstance(node, ast.JoinedStr):
        return any(_has_nonascii_str(v) for v in node.values)
    return False


def _is_print_or_log_call(node):
    if isinstance(node.func, ast.Name) and node.func.id == "print":
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in LOG_METHODS:
        value = node.func.value
        if isinstance(value, ast.Name) and value.id in LOGGER_NAMES:
            return True
    return False


def _find_violations():
    """Return a list of (relative_path, lineno) for every print()/logger
    call found with a literal non-ASCII string argument, outside EXEMPT_FILES."""
    violations = []

    for path in sorted(REPO_ROOT.rglob("*.py")):
        relative = path.relative_to(REPO_ROOT)
        if any(part in EXCLUDE_DIRS for part in relative.parts):
            continue
        if relative.as_posix() in EXEMPT_FILES:
            continue

        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_print_or_log_call(node):
                args = list(node.args) + [kw.value for kw in node.keywords]
                if any(_has_nonascii_str(arg) for arg in args):
                    violations.append((relative.as_posix(), node.lineno))

    return violations


class TestNoUnicodeInConsoleOutput(unittest.TestCase):

    def test_no_literal_non_ascii_in_print_or_logging_calls(self):
        violations = _find_violations()
        if violations:
            details = "\n".join(f"  {path}:{lineno}" for path, lineno in violations)
            self.fail(
                "Found literal non-ASCII characters in print()/logger calls - "
                "this crashes on Windows consoles using cp1252 unless the file "
                "is added to EXEMPT_FILES alongside a sys.stdout.reconfigure() "
                f"call:\n{details}"
            )

    def test_exempt_files_still_exist(self):
        """Catch a stale entry if an exempted file is ever renamed/removed."""
        for relative in EXEMPT_FILES:
            self.assertTrue(
                (REPO_ROOT / relative).is_file(),
                f"EXEMPT_FILES lists '{relative}' but it no longer exists - remove the entry",
            )


if __name__ == "__main__":
    unittest.main()
