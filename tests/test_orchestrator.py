"""
Unit tests for orchestrator.py - the scheduling/run-loop entry point, at
0% coverage until this vague. Real scheduling (schedule.every()...at()
actually firing at the right wall-clock time) is deliberately NOT tested
here - that was already verified manually in real conditions (Vague 3a).
What's tested is each job's own logic in isolation: metrics bookkeeping,
error handling, and two behavior fixes made alongside these tests (see
each test's docstring for the "before" behavior being guarded against):

- get_threat_count() now returns None on a DB read failure, not 0 (0
  would be indistinguishable from a real empty table), and
  run_daily_pipeline() propagates that None correctly instead of
  computing a nonsensical delta or a false "0 new threats".
- run_weekly_pipeline()'s 3 steps (validate_data_quality,
  deduplicate_threats, generate_weekly_report) now return True/False
  instead of swallowing their own exceptions with no way for the caller
  to know - previously the outer function could never actually observe
  a failure (nothing propagated to its try/except), so it always logged
  "✅ réussi" and never updated any metric, even when every step failed.

PipelineOrchestrator.__init__() always reads the real, hardcoded
'logs/orchestrator_metrics.json' (not parameterized), and save_metrics()
writes to it too - OrchestratorTestBase below backs that file up and
restores it around every test, then resets self.metrics to a known
baseline right after construction, so assertions never depend on
whatever real accumulated state happens to be in that file.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

import orchestrator as orchestrator_module
from orchestrator import PipelineOrchestrator, PipelineScheduler

METRICS_FILE = 'logs/orchestrator_metrics.json'


def _make_threats_db(path, rows=None):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "threat_id TEXT UNIQUE, severity TEXT, threat_type TEXT, source TEXT)"
    )
    for row in (rows or []):
        conn.execute(
            "INSERT INTO threats (threat_id, severity, threat_type, source) VALUES (?, ?, ?, ?)",
            row,
        )
    conn.commit()
    conn.close()


class OrchestratorTestBase(unittest.TestCase):

    def setUp(self):
        self._had_metrics_file = os.path.exists(METRICS_FILE)
        if self._had_metrics_file:
            with open(METRICS_FILE, 'r', encoding='utf-8') as f:
                self._original_metrics_content = f.read()

        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)

    def tearDown(self):
        os.remove(self.db_path)
        if self._had_metrics_file:
            with open(METRICS_FILE, 'w', encoding='utf-8') as f:
                f.write(self._original_metrics_content)
        elif os.path.exists(METRICS_FILE):
            os.remove(METRICS_FILE)

    def _fresh_orchestrator(self, db_path=None):
        """A PipelineOrchestrator with a known-baseline self.metrics,
        independent of whatever the real metrics file currently holds."""
        orch = PipelineOrchestrator(db_path=db_path or self.db_path)
        orch.metrics = {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'last_threats_collected': 0,
            'last_run_time': None,
            'next_run_time': None,
        }
        return orch


class WeeklyReportFileMixin:
    """generate_weekly_report() writes a real, dated file under logs/ -
    back it up/restore it the same way as the metrics file."""

    def setUp(self):
        super().setUp()
        self._report_path = f"logs/weekly_report_{datetime.now().strftime('%Y%m%d')}.json"
        self._report_existed = os.path.exists(self._report_path)
        if self._report_existed:
            with open(self._report_path, 'r', encoding='utf-8') as f:
                self._report_original = f.read()

    def tearDown(self):
        if self._report_existed:
            with open(self._report_path, 'w', encoding='utf-8') as f:
                f.write(self._report_original)
        elif os.path.exists(self._report_path):
            os.remove(self._report_path)
        super().tearDown()


class TestGetThreatCount(OrchestratorTestBase):

    def test_returns_real_count(self):
        _make_threats_db(self.db_path, rows=[(f'T-{i}', 'low', 'other', 'TEST') for i in range(5)])
        orch = self._fresh_orchestrator()
        self.assertEqual(orch.get_threat_count(), 5)

    def test_returns_none_on_db_error_not_zero(self):
        """The fix this vague made: 0 would be indistinguishable from a
        real empty table."""
        conn = sqlite3.connect(self.db_path)  # no threats table at all
        conn.close()
        orch = self._fresh_orchestrator()
        self.assertIsNone(orch.get_threat_count())


class TestRunDailyPipeline(OrchestratorTestBase):

    def test_success_updates_metrics_and_computes_delta(self):
        _make_threats_db(self.db_path, rows=[(f'T-{i}', 'low', 'other', 'TEST') for i in range(10)])
        orch = self._fresh_orchestrator()

        def fake_run_pipeline():
            conn = sqlite3.connect(self.db_path)
            for i in range(3):
                conn.execute(
                    "INSERT INTO threats (threat_id, severity, threat_type, source) "
                    "VALUES (?, 'low', 'other', 'TEST')",
                    (f'NEW-{i}',),
                )
            conn.commit()
            conn.close()

        with patch('pipeline.process.run_pipeline', side_effect=fake_run_pipeline):
            orch.run_daily_pipeline()

        self.assertEqual(orch.metrics['successful_runs'], 1)
        self.assertEqual(orch.metrics['failed_runs'], 0)
        self.assertEqual(orch.metrics['total_runs'], 1)
        self.assertEqual(orch.metrics['last_threats_collected'], 3)
        self.assertIsNotNone(orch.metrics['last_run_time'])

    def test_pipeline_exception_marks_failed_run(self):
        _make_threats_db(self.db_path, rows=[('T-1', 'low', 'other', 'TEST')])
        orch = self._fresh_orchestrator()

        with patch('pipeline.process.run_pipeline', side_effect=RuntimeError("boom")):
            orch.run_daily_pipeline()

        self.assertEqual(orch.metrics['failed_runs'], 1)
        self.assertEqual(orch.metrics['successful_runs'], 0)
        self.assertEqual(orch.metrics['total_runs'], 1)

    def test_db_read_failure_propagates_none_not_a_fake_zero(self):
        """The exact scenario the user's decision targeted: a DB read
        failure before and/or after the pipeline must surface as None,
        never silently become 0 (which would look identical to a real
        "0 new threats" run)."""
        conn = sqlite3.connect(self.db_path)  # no threats table -> get_threat_count() -> None
        conn.close()
        orch = self._fresh_orchestrator()

        with patch('pipeline.process.run_pipeline'):
            orch.run_daily_pipeline()

        self.assertIsNone(orch.metrics['last_threats_collected'])
        # The pipeline call itself didn't raise - only measuring its
        # effect failed - so this still counts as a successful run.
        self.assertEqual(orch.metrics['successful_runs'], 1)
        self.assertEqual(orch.metrics['failed_runs'], 0)


class TestValidateDataQuality(OrchestratorTestBase):

    def test_returns_true_on_success(self):
        _make_threats_db(self.db_path, rows=[('T-1', 'critical', 'prompt_injection', 'CVE')])
        orch = self._fresh_orchestrator()
        self.assertTrue(orch.validate_data_quality())

    def test_returns_false_on_db_error(self):
        conn = sqlite3.connect(self.db_path)
        conn.close()
        orch = self._fresh_orchestrator()
        self.assertFalse(orch.validate_data_quality())


class TestDeduplicateThreats(OrchestratorTestBase):

    def test_removes_duplicates_keeps_the_latest(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "threat_id TEXT, severity TEXT, threat_type TEXT, source TEXT)"
        )
        conn.execute("INSERT INTO threats (threat_id) VALUES ('DUP-1')")
        conn.execute("INSERT INTO threats (threat_id) VALUES ('DUP-1')")
        conn.execute("INSERT INTO threats (threat_id) VALUES ('UNIQUE-1')")
        conn.commit()
        conn.close()

        orch = self._fresh_orchestrator()
        self.assertTrue(orch.deduplicate_threats())

        conn = sqlite3.connect(self.db_path)
        rows = [r[0] for r in conn.execute("SELECT threat_id FROM threats ORDER BY id").fetchall()]
        conn.close()
        # Only the higher-id (later) DUP-1 row survives.
        self.assertEqual(rows, ['DUP-1', 'UNIQUE-1'])

    def test_returns_false_on_db_error(self):
        conn = sqlite3.connect(self.db_path)
        conn.close()
        orch = self._fresh_orchestrator()
        self.assertFalse(orch.deduplicate_threats())


class TestGenerateWeeklyReport(WeeklyReportFileMixin, OrchestratorTestBase):

    def test_returns_true_and_writes_a_correct_report(self):
        _make_threats_db(self.db_path, rows=[
            ('T-1', 'critical', 'prompt_injection', 'CVE'),
            ('T-2', 'high', 'other', 'GitHub'),
        ])
        orch = self._fresh_orchestrator()
        self.assertTrue(orch.generate_weekly_report())

        with open(self._report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        self.assertEqual(report['total_threats'], 2)
        self.assertEqual(report['critical'], 1)
        self.assertEqual(report['high'], 1)

    def test_returns_false_on_db_error(self):
        conn = sqlite3.connect(self.db_path)
        conn.close()
        orch = self._fresh_orchestrator()
        self.assertFalse(orch.generate_weekly_report())


class TestRunWeeklyPipeline(WeeklyReportFileMixin, OrchestratorTestBase):

    def test_all_steps_succeed_marks_run_successful(self):
        _make_threats_db(self.db_path, rows=[('T-1', 'low', 'other', 'TEST')])
        orch = self._fresh_orchestrator()

        result = orch.run_weekly_pipeline()

        self.assertTrue(result)
        self.assertEqual(orch.metrics['successful_runs'], 1)
        self.assertEqual(orch.metrics['failed_runs'], 0)
        self.assertEqual(orch.metrics['total_runs'], 1)

    def test_every_step_failing_is_now_visible_not_silently_successful(self):
        """Before this vague's fix: validate_data_quality,
        deduplicate_threats, and generate_weekly_report each caught their
        own exceptions and always returned normally, so
        run_weekly_pipeline()'s own try/except never triggered - this
        exact scenario (DB errors in all 3 steps) used to log "✅ réussi"
        and update no metric at all. Confirms that's fixed."""
        conn = sqlite3.connect(self.db_path)  # no threats table -> all 3 steps fail internally
        conn.close()
        orch = self._fresh_orchestrator()

        result = orch.run_weekly_pipeline()

        self.assertFalse(result)
        self.assertEqual(orch.metrics['failed_runs'], 1)
        self.assertEqual(orch.metrics['successful_runs'], 0)
        self.assertEqual(orch.metrics['total_runs'], 1)

    def test_a_single_failing_step_still_marks_the_whole_run_failed(self):
        """One step succeeding must not hide the other(s) failing."""
        _make_threats_db(self.db_path, rows=[('T-1', 'low', 'other', 'TEST')])
        orch = self._fresh_orchestrator()

        with patch.object(orch, 'generate_weekly_report', return_value=False):
            result = orch.run_weekly_pipeline()

        self.assertFalse(result)
        self.assertEqual(orch.metrics['failed_runs'], 1)
        self.assertEqual(orch.metrics['successful_runs'], 0)


class TestMetricsPersistence(OrchestratorTestBase):

    def test_save_and_load_round_trip(self):
        orch = self._fresh_orchestrator()
        orch.metrics['total_runs'] = 42
        orch.save_metrics()

        reloaded = PipelineOrchestrator(db_path=self.db_path)
        self.assertEqual(reloaded.metrics['total_runs'], 42)

    def test_load_metrics_tolerates_a_missing_file(self):
        if os.path.exists(METRICS_FILE):
            os.remove(METRICS_FILE)
        orch = PipelineOrchestrator(db_path=self.db_path)
        self.assertEqual(orch.metrics['total_runs'], 0)  # __init__'s default

    def test_load_metrics_tolerates_corrupt_json(self):
        with open(METRICS_FILE, 'w', encoding='utf-8') as f:
            f.write('{not valid json')
        orch = PipelineOrchestrator(db_path=self.db_path)
        self.assertEqual(orch.metrics['total_runs'], 0)  # falls back to __init__'s default


class TestHealthStatus(OrchestratorTestBase):

    def test_reflects_current_metrics_and_db_state(self):
        _make_threats_db(self.db_path, rows=[(f'T-{i}', 'low', 'other', 'TEST') for i in range(7)])
        orch = self._fresh_orchestrator()
        orch.metrics.update({'total_runs': 4, 'successful_runs': 4, 'failed_runs': 0})

        health = orch.get_health_status()

        self.assertEqual(health['status'], '🟢 HEALTHY')
        self.assertEqual(health['current_threats'], 7)
        self.assertEqual(health['success_rate'], 100.0)

    def test_warning_status_when_failures_present(self):
        orch = self._fresh_orchestrator()
        orch.metrics.update({'total_runs': 4, 'successful_runs': 3, 'failed_runs': 1})
        health = orch.get_health_status()
        self.assertEqual(health['status'], '🟠 WARNING')

    def test_print_health_status_does_not_raise_even_with_a_db_error(self):
        conn = sqlite3.connect(self.db_path)  # no threats table -> current_threats is None
        conn.close()
        orch = self._fresh_orchestrator()
        orch.print_health_status()  # only checking this doesn't raise


class TestPipelineSchedulerJobs(unittest.TestCase):
    """schedule_jobs() registers the real jobs - not that they fire at
    the right wall-clock time (verified manually, see module docstring)."""

    def setUp(self):
        orchestrator_module.schedule.clear()

    def tearDown(self):
        orchestrator_module.schedule.clear()

    def test_registers_daily_weekly_and_health_jobs(self):
        scheduler = PipelineScheduler()
        scheduler.schedule_jobs()

        tags = set()
        for job in orchestrator_module.schedule.jobs:
            tags.update(job.tags)

        self.assertIn('daily', tags)
        self.assertIn('weekly', tags)
        self.assertIn('health', tags)


class TestPipelineSchedulerStartTestMode(OrchestratorTestBase):

    def setUp(self):
        super().setUp()
        orchestrator_module.schedule.clear()

    def tearDown(self):
        orchestrator_module.schedule.clear()
        super().tearDown()

    def test_test_mode_runs_daily_pipeline_once_and_returns(self):
        with patch('pipeline.process.run_pipeline') as mock_run:
            scheduler = PipelineScheduler()
            scheduler.orchestrator.db_path = self.db_path
            scheduler.orchestrator.metrics = {
                'total_runs': 0, 'successful_runs': 0, 'failed_runs': 0,
                'last_threats_collected': 0, 'last_run_time': None, 'next_run_time': None,
            }
            _make_threats_db(self.db_path, rows=[('T-1', 'low', 'other', 'TEST')])

            scheduler.start(test_mode=True)

            mock_run.assert_called_once()
        self.assertTrue(scheduler.is_running)

    def test_stop_clears_is_running(self):
        scheduler = PipelineScheduler()
        scheduler.is_running = True
        scheduler.stop()
        self.assertFalse(scheduler.is_running)


if __name__ == '__main__':
    unittest.main()
