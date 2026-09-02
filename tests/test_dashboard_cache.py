"""
Tests for the @st.cache_data TTLs added to dashboard/main.py,
dashboard/pages/{intelligence,catalog,operations}.py (see ARCHITECTURE.md's
Caching section). Before this, only the DB connection itself was cached
(@st.cache_resource) - no query result was, so every widget interaction
re-ran every query on the page (Streamlit reruns the whole script on
every interaction).

Scope, deliberately: a "TTL is configured as intended" check per function
(cheap, deterministic), plus one concrete check per parameterized function
proving Streamlit's cache key genuinely varies by argument (agent_name,
days) - a wrong key there would silently leak one agent's/filter's data
into another's, the one failure mode worth guarding against. Testing real
TTL *expiration* is deliberately NOT automated here - it would mean either
a real sleep (300s for the 5-minute-TTL functions makes that impractical)
or mocking Streamlit's internal cache clock (fragile, tied to
implementation details). That expiration behavior was instead verified
concretely by hand against the real database when this file was added -
main.py's 30s TTL was chosen specifically because a real 30s wait was
practical to observe directly: a newly inserted threat stayed invisible
through the TTL window and appeared right after, never early, never
stuck forever.

Why every check below runs in a subprocess rather than importing the page
file in-process: these page files execute top-level Streamlit calls
(st.set_page_config, st.form/st.button, an API-key gate that calls
st.stop() in operations.py) that assume a real Streamlit script run.
Loading them directly via importlib ("bare mode") executes those calls
with no ScriptRunContext - individually harmless (they no-op or raise
partway through, leaving every function defined before that point still
bound on the module object) - but doing this inside the same process as
pytest was confirmed to corrupt Streamlit's shared widget/form-nesting
state, which then broke unrelated AppTest-based tests running later in
the same session (test_main_page.py, test_operations_page.py,
test_scan_persistence.py all started failing with spurious "st.button()
can't be used in an st.form()" errors once a bare import of the same
files ran earlier in the process). A subprocess is a real, disposable
Python process per check, so nothing it does to Streamlit's internals
can leak into the test runner's own process.
"""

import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_subprocess_json(code: str) -> dict:
    """Run `code` in a fresh interpreter from the repo root and parse its
    last stdout line as JSON. Streamlit's own "missing ScriptRunContext"
    warnings go to stderr/logging and are not captured, so stdout stays
    clean for the JSON payload."""
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"subprocess failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    last_line = result.stdout.strip().splitlines()[-1]
    return json.loads(last_line)


_LOAD_BARE_PREAMBLE = """
import importlib.util, json, logging
from pathlib import Path
logging.disable(logging.CRITICAL)

_DASHBOARD_DIR = Path(r"{dashboard_dir}")

def load_bare(relative_path):
    path = _DASHBOARD_DIR / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        pass  # expected: page rendering hits a no-runtime widget call / st.stop()
    return module
""".format(dashboard_dir=REPO_ROOT / "dashboard")


class TestMainPageCacheTTL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.info = _run_subprocess_json(_LOAD_BARE_PREAMBLE + """
from pathlib import Path
mod = load_bare("main.py")
print(json.dumps({"get_platform_stats_ttl": mod.get_platform_stats._info.ttl}))
""")

    def test_get_platform_stats_ttl_is_30_seconds(self):
        """Short on purpose - see the docstring on the function itself
        and ARCHITECTURE.md: this file already had a real hardcoded-
        metrics bug this session, so it gets the smallest TTL in the app
        as a deliberate safety margin, not because the underlying data
        changes that fast."""
        self.assertEqual(self.info["get_platform_stats_ttl"], 30)


class TestIntelligencePageCacheTTL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.info = _run_subprocess_json(_LOAD_BARE_PREAMBLE + """
mod = load_bare("pages/intelligence.py")

seven_day = mod.get_threat_trends(days=7)
ninety_day = mod.get_threat_trends(days=90)

print(json.dumps({
    "get_threat_stats_ttl": mod.get_threat_stats._info.ttl,
    "get_latest_threats_ttl": mod.get_latest_threats._info.ttl,
    "get_threat_trends_ttl": mod.get_threat_trends._info.ttl,
    "trends_7_len": len(seven_day),
    "trends_90_len": len(ninety_day),
    "trends_frames_equal": seven_day.equals(ninety_day),
}))
""")

    def test_get_threat_stats_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_threat_stats_ttl"], 300)

    def test_get_latest_threats_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_latest_threats_ttl"], 300)

    def test_get_threat_trends_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_threat_trends_ttl"], 300)

    def test_get_threat_trends_cache_key_varies_by_days(self):
        """The one parameterized, genuinely-varied-by-a-slider function
        on this page - confirmed here rather than assumed, since a cache
        key that ignored `days` would silently show one window's data
        under every slider position."""
        # A 90-day window can only cover the same or more days than a
        # 7-day window over the same real data - if the cache key ignored
        # `days`, both calls would return the exact same frame.
        self.assertGreaterEqual(self.info["trends_90_len"], self.info["trends_7_len"])
        self.assertFalse(self.info["trends_frames_equal"])


class TestCatalogPageCacheTTL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.info = _run_subprocess_json(_LOAD_BARE_PREAMBLE + """
mod = load_bare("pages/catalog.py")
print(json.dumps({
    "get_all_threats_ttl": mod.get_all_threats._info.ttl,
    "get_filter_options_ttl": mod.get_filter_options._info.ttl,
}))
""")

    def test_get_all_threats_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_all_threats_ttl"], 300)

    def test_get_filter_options_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_filter_options_ttl"], 300)


class TestOperationsPageCacheTTL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.info = _run_subprocess_json(_LOAD_BARE_PREAMBLE + """
import sqlite3
mod = load_bare("pages/operations.py")

from monitoring import monitoring_store

agent_a = "cache-scope-test-A"
agent_b = "cache-scope-test-B"
try:
    for _ in range(3):
        monitoring_store.write_log(
            agent_name=agent_a, prompt="p", response="r",
            risk_level="low", alert_triggered=False, detected_threats=[],
        )
    monitoring_store.write_log(
        agent_name=agent_b, prompt="p", response="r",
        risk_level="low", alert_triggered=False, detected_threats=[],
    )

    stats_a = mod._cached_get_statistics(agent_a)
    stats_b = mod._cached_get_statistics(agent_b)
finally:
    conn = sqlite3.connect("data/monitoring.db")
    conn.execute("DELETE FROM monitoring_logs WHERE agent_name IN (?, ?)", (agent_a, agent_b))
    conn.execute("DELETE FROM monitoring_alerts WHERE agent_name IN (?, ?)", (agent_a, agent_b))
    conn.commit()
    conn.close()

print(json.dumps({
    "get_all_threats_ttl": mod.get_all_threats._info.ttl,
    "list_agents_ttl": mod._cached_list_agents._info.ttl,
    "get_statistics_ttl": mod._cached_get_statistics._info.ttl,
    "get_alerts_ttl": mod._cached_get_alerts._info.ttl,
    "stats_a_requests": stats_a["total_requests_logged"],
    "stats_b_requests": stats_b["total_requests_logged"],
}))
""")

    def test_get_all_threats_ttl_is_5_minutes(self):
        self.assertEqual(self.info["get_all_threats_ttl"], 300)

    def test_cached_list_agents_ttl_is_60_seconds(self):
        """A fallback safety net only - register/deactivate explicitly
        call .clear() on this at the point of mutation (see
        dashboard/pages/operations.py), so 60s only matters for a change
        made from elsewhere (the API, another browser tab)."""
        self.assertEqual(self.info["list_agents_ttl"], 60)

    def test_cached_get_statistics_ttl_is_30_seconds(self):
        """The one dashboard view meant to look close to live production
        monitoring - shortest non-main.py TTL in the app on purpose."""
        self.assertEqual(self.info["get_statistics_ttl"], 30)

    def test_cached_get_alerts_ttl_is_30_seconds(self):
        self.assertEqual(self.info["get_alerts_ttl"], 30)

    def test_cached_get_statistics_cache_key_varies_by_agent_name(self):
        """The critical scoping check for this page: a cache key that
        ignored agent_name would show one agent's request/alert counts
        under every agent's health tile."""
        self.assertEqual(self.info["stats_a_requests"], 3)
        self.assertEqual(self.info["stats_b_requests"], 1)


if __name__ == "__main__":
    unittest.main()
