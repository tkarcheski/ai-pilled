import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.performance import benchmark


class PerformanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.configure([sys.executable, '-c',
                        'import os; assert not any(k.startswith("GIT_") for k in os.environ)'])

    def configure(self, command):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'benchmark': command}}))

    def measure(self, duration, save=False):
        with patch('ai_pilled.performance.time.perf_counter', side_effect=[0, duration]):
            return benchmark(self.repo, runs=1, save_baseline=save)

    def test_baseline_is_explicit_and_missing_one_is_incomplete(self):
        with patch('ai_pilled.performance.run') as command:
            self.assertEqual(benchmark(self.repo).status, 'incomplete')
            command.assert_not_called()
        with patch.dict(os.environ, {'GIT_DIR': '/not-this-repo'}):
            self.assertEqual(self.measure(1, save=True).status, 'pass')

    def test_regression_does_not_rewrite_baseline(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled' / 'benchmark.json'
        saved = path.read_bytes()
        result = self.measure(1.3)
        self.assertEqual(result.status, 'fail')
        self.assertAlmostEqual(result.metrics['regression_percent'], 30)
        self.assertEqual(path.read_bytes(), saved)
        self.assertEqual(self.measure(.9).status, 'pass')

    def test_median_resists_one_slow_sample(self):
        with patch('ai_pilled.performance.time.perf_counter', side_effect=[0, 1, 0, 20, 0, 2]):
            result = benchmark(self.repo, runs=3, save_baseline=True)
        self.assertEqual(result.metrics['median_seconds'], 2)

    def test_changed_command_requires_explicit_rebaseline(self):
        self.measure(1, save=True)
        self.configure([sys.executable, '-c', 'pass'])
        self.assertEqual(benchmark(self.repo).status, 'incomplete')
        self.assertEqual(self.measure(1, save=True).status, 'pass')

    def test_failed_command_does_not_replace_baseline(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled' / 'benchmark.json'
        saved = path.read_bytes()
        self.configure([sys.executable, '-c', 'raise SystemExit(1)'])
        self.assertEqual(benchmark(self.repo, save_baseline=True).status, 'incomplete')
        self.assertEqual(path.read_bytes(), saved)

    def test_corrupt_baseline_and_invalid_options_are_incomplete(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled' / 'benchmark.json'
        path.write_text('[]')
        self.assertEqual(benchmark(self.repo).status, 'incomplete')
        for kwargs in ({'runs': 0}, {'runs': 11}, {'maximum_regression': float('nan')}):
            self.assertEqual(benchmark(self.repo, **kwargs).status, 'incomplete')

    def test_baseline_special_and_oversized_files_do_not_run_commands(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled/benchmark.json'
        for kind in ('fifo', 'symlink', 'oversized'):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'symlink':
                    path.symlink_to(self.repo / '.ai-pilled.json')
                else:
                    path.write_bytes(b' ' * 10_001)
                with patch('ai_pilled.performance.run') as command:
                    self.assertEqual(benchmark(self.repo).status, 'incomplete')
                command.assert_not_called()

    def test_contended_benchmark_lock_never_runs_command_or_replaces_baseline(self):
        self.measure(1, save=True)
        state = self.repo / '.ai-pilled'
        before = (state / 'benchmark.json').read_bytes()
        with (state / 'benchmark.lock').open('rb') as held, patch('ai_pilled.locking.LOCK_TIMEOUT', 0.02):
            fcntl.flock(held, fcntl.LOCK_EX)
            with patch('ai_pilled.performance.run') as command:
                result = benchmark(self.repo, save_baseline=True)
            self.assertEqual(result.status, 'incomplete')
            self.assertIn('lock is busy', result.findings[0].message)
            command.assert_not_called()
        self.assertEqual((state / 'benchmark.json').read_bytes(), before)

    def test_special_benchmark_lock_is_preserved(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        path = state / 'benchmark.lock'
        os.mkfifo(path)
        with patch('ai_pilled.performance.run') as command:
            result = benchmark(self.repo, save_baseline=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(path.is_fifo())
        command.assert_not_called()

    def test_extreme_baselines_never_corrupt_history_or_change_baseline(self):
        from ai_pilled.state import history
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled/benchmark.json'
        original = json.loads(path.read_text())
        for value in (10 ** 400, 5e-324):
            with self.subTest(value_type=type(value).__name__):
                path.write_text(json.dumps(dict(original, median_seconds=value)))
                before = path.read_bytes()
                with patch('ai_pilled.performance.run') as command:
                    result = self.measure(1)
                self.assertEqual(result.status, 'incomplete')
                if isinstance(value, int):
                    command.assert_not_called()
                self.assertEqual(path.read_bytes(), before)
                json.dumps(result.to_dict(), allow_nan=False)
                self.assertEqual(history(self.repo)[-1]['report']['status'], 'incomplete')

    def test_invalid_timings_never_replace_saved_baseline(self):
        from ai_pilled.state import history
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled/benchmark.json'
        before = path.read_bytes()
        for duration in (0, -1, float('inf'), float('nan')):
            with self.subTest(duration=str(duration)):
                result = self.measure(duration, save=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.metrics, {})
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(history(self.repo)[-1]['report']['status'], 'incomplete')

    def test_invalid_numeric_budgets_do_not_run_commands(self):
        for value in (True, '20', 10 ** 400, float('inf')):
            with self.subTest(value_type=type(value).__name__):
                with patch('ai_pilled.performance.run') as command:
                    result = benchmark(self.repo, maximum_regression=value)
                self.assertEqual(result.status, 'incomplete')
                command.assert_not_called()
                json.dumps(result.to_dict(), allow_nan=False)

    def test_finite_samples_with_overflowing_median_do_not_replace_baseline(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled/benchmark.json'
        before = path.read_bytes()
        with patch('ai_pilled.performance.time.perf_counter', side_effect=[0, 1e308, 0, 1e308]):
            result = benchmark(self.repo, runs=2, save_baseline=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.metrics, {})
        self.assertEqual(path.read_bytes(), before)

    def test_boolean_baseline_schema_version_is_rejected(self):
        self.measure(1, save=True)
        path = self.repo / '.ai-pilled/benchmark.json'
        data = json.loads(path.read_text())
        data['version'] = True
        path.write_text(json.dumps(data))
        with patch('ai_pilled.performance.run') as command:
            result = benchmark(self.repo)
        self.assertEqual(result.status, 'incomplete')
        command.assert_not_called()
