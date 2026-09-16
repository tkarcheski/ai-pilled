import contextlib
from datetime import datetime, timezone
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.refactor import RefactorReport
from ai_pilled.scheduling import nightly_refactor, watch


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        fake = patch('ai_pilled.scheduling.refactor', return_value=RefactorReport('refactor'))
        self.refactor = fake.start()
        self.addCleanup(fake.stop)

    def run_at(self, value, **kwargs):
        return nightly_refactor(self.repo, now=datetime.fromisoformat(value), **kwargs)

    def test_not_due_does_not_run_refactor(self):
        result = self.run_at('2026-09-16T02:59:00+00:00')
        self.assertEqual(result.action, 'waiting')
        self.assertEqual(result.next_date, '2026-09-16')
        self.refactor.assert_not_called()

    def test_due_runs_once_per_date_and_survives_new_invocation(self):
        self.assertEqual(self.run_at('2026-09-16T03:00:00+00:00').action, 'ran')
        self.assertEqual(self.run_at('2026-09-16T23:59:00+00:00').action, 'already-attempted')
        self.assertEqual(self.refactor.call_count, 1)
        self.assertEqual(self.run_at('2026-09-17T03:00:00+00:00').action, 'ran')
        self.assertEqual(self.refactor.call_count, 2)

    def test_timezone_and_dst_fallback_do_not_repeat_a_day(self):
        options = {'at': '01:30', 'timezone_name': 'America/Chicago'}
        self.assertEqual(self.run_at('2026-11-01T06:29:00+00:00', **options).action, 'waiting')
        self.assertEqual(self.run_at('2026-11-01T06:30:00+00:00', **options).action, 'ran')
        self.assertEqual(self.run_at('2026-11-01T07:30:00+00:00', **options).action, 'already-attempted')
        self.assertEqual(self.refactor.call_count, 1)

    def test_spring_forward_runs_after_missing_wall_time(self):
        options = {'at': '02:30', 'timezone_name': 'America/Chicago'}
        self.assertEqual(self.run_at('2026-03-08T07:59:00+00:00', **options).action, 'waiting')
        self.assertEqual(self.run_at('2026-03-08T08:00:00+00:00', **options).action, 'ran')

    def test_failed_attempt_needs_explicit_retry_that_day(self):
        failed = RefactorReport('refactor')
        failed.add('failure', 'Repair failed')
        self.refactor.return_value = failed
        self.assertEqual(self.run_at('2026-09-16T03:00:00+00:00').status, 'fail')
        result = self.run_at('2026-09-16T04:00:00+00:00')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'already-attempted')
        self.refactor.return_value = RefactorReport('refactor')
        self.assertEqual(self.run_at('2026-09-16T04:00:00+00:00', retry=True).status, 'pass')
        self.assertEqual(self.refactor.call_count, 2)

    def test_crashed_attempt_is_reserved_before_work(self):
        self.refactor.side_effect = RuntimeError('Simulated process failure')
        with self.assertRaises(RuntimeError):
            self.run_at('2026-09-16T03:00:00+00:00')
        self.refactor.side_effect = None
        result = self.run_at('2026-09-16T04:00:00+00:00')
        self.assertEqual(result.action, 'already-attempted')
        self.assertEqual(result.result['status'], 'running')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(self.refactor.call_count, 1)

    def test_concurrent_scheduler_returns_busy_without_waiting(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        with (state / 'nightly-refactor.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_at('2026-09-16T03:00:00+00:00')
        self.assertEqual(result.action, 'busy')
        self.refactor.assert_not_called()

    def test_invalid_clock_timezone_and_time_are_incomplete(self):
        for options in ({'at': '25:00'}, {'timezone_name': 'Nonexistent/Zone'},
                        {'now': datetime(2026, 9, 16, 3)}):
            self.assertEqual(nightly_refactor(self.repo, **options).status, 'incomplete')
        self.refactor.assert_not_called()

    def test_special_schedule_files_fail_without_blocking(self):
        self.run_at('2026-09-16T03:00:00+00:00')
        state = self.repo / '.ai-pilled'
        record = next(state.glob('nightly-*.json'))
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                   PYTHONDONTWRITEBYTECODE='1')
        script = ('import json,sys; from datetime import datetime; '
                  'from ai_pilled.scheduling import nightly_refactor; '
                  'r=nightly_refactor(sys.argv[1], now=datetime.fromisoformat("2026-09-16T02:00:00+00:00")); '
                  'print(json.dumps(r.to_dict()))')
        for path in (record, state / 'nightly-refactor.lock'):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.unlink()
                os.mkfifo(path)
                try:
                    result = subprocess.run([sys.executable, '-c', script, str(self.repo)],
                                            env=env, capture_output=True, timeout=3, check=True)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'incomplete')
                    self.assertEqual(report['action'], 'not-run')
                    self.assertTrue(path.is_fifo())
                finally:
                    path.unlink()
                    path.write_bytes(original)
        self.assertEqual(self.refactor.call_count, 1)

    def test_schedule_symlinks_and_oversized_records_remain_untouched(self):
        self.run_at('2026-09-16T03:00:00+00:00')
        path = next((self.repo / '.ai-pilled').glob('nightly-*.json'))
        path.write_bytes(b'x' * 16_001)
        self.assertEqual(self.run_at('2026-09-17T03:00:00+00:00').status, 'incomplete')
        self.assertEqual(path.stat().st_size, 16_001)
        path.unlink()
        target = self.repo / 'user-file'
        target.write_text('preserve me')
        path.symlink_to(target)
        self.assertEqual(self.run_at('2026-09-17T03:00:00+00:00').status, 'incomplete')
        self.assertTrue(path.is_symlink())
        self.assertEqual(target.read_text(), 'preserve me')
        self.assertEqual(self.refactor.call_count, 1)

    def test_corrupt_state_is_not_silently_reset(self):
        self.run_at('2026-09-16T03:00:00+00:00')
        path = next((self.repo / '.ai-pilled').glob('nightly-*.json'))
        path.write_text('{invalid json')
        self.assertEqual(self.run_at('2026-09-17T03:00:00+00:00').status, 'incomplete')
        self.assertEqual(path.read_text(), '{invalid json')
        self.assertEqual(self.refactor.call_count, 1)

    def test_foreground_watch_stops_with_interrupt_without_installing_job(self):
        # Replace this module's reference; patching time.sleep also interrupts subprocess cleanup.
        with patch('ai_pilled.scheduling.datetime') as clock, patch('ai_pilled.scheduling.time') as timer, contextlib.redirect_stdout(io.StringIO()) as output:
            timer.sleep.side_effect = KeyboardInterrupt
            clock.now.return_value = datetime(2026, 9, 16, 2, tzinfo=timezone.utc)
            self.assertEqual(watch(self.repo), 130)
        self.assertEqual(json.loads(output.getvalue())['action'], 'waiting')
        self.refactor.assert_not_called()

    def test_state_parent_swaps_never_start_work_or_write_outside(self):
        from ai_pilled.scheduling import read_attempt
        from ai_pilled.state import atomic_json, directory
        original_replace = os.replace
        for moment in ('lock', 'read', 'publish', 'rename'):
            with self.subTest(moment=moment):
                root = self.repo / moment
                root.mkdir()
                subprocess.run(['git', 'init', '-q', str(root)], check=True)
                (root / '.gitignore').write_text('.ai-pilled/\n')
                parent = root / '.ai-pilled'
                parent.mkdir()
                outside = root / 'outside'
                outside.mkdir()
                (outside / 'marker').write_text('preserve')

                def swap(parent=parent, root=root, outside=outside):
                    parent.rename(root / 'original')
                    parent.symlink_to(outside, target_is_directory=True)

                def before_lock(repo):
                    path = directory(repo)
                    swap()
                    return path

                def before_read(*args, **kwargs):
                    swap()
                    return read_attempt(*args, **kwargs)

                def before_publish(*args, **kwargs):
                    swap()
                    return atomic_json(*args, **kwargs)

                def before_rename(*args, **kwargs):
                    swap()
                    return original_replace(*args, **kwargs)

                target, replacement = {
                    'lock': ('ai_pilled.scheduling.directory', before_lock),
                    'read': ('ai_pilled.scheduling.read_attempt', before_read),
                    'publish': ('ai_pilled.scheduling.atomic_json', before_publish),
                    'rename': ('ai_pilled.state.os.replace', before_rename),
                }[moment]
                with patch(target, side_effect=replacement):
                    result = nightly_refactor(root, now=datetime(2026, 9, 16, 4, tzinfo=timezone.utc))
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'not-run')
                self.refactor.assert_not_called()
                self.assertEqual(sorted(path.name for path in outside.iterdir()), ['marker'])
                self.assertEqual((outside / 'marker').read_text(), 'preserve')
                self.assertEqual(list((root / 'original').glob('.ai-pilled-*.tmp')), [])

    def test_unrepresentable_next_dates_are_incomplete_before_work(self):
        result = self.run_at('9999-12-31T03:00:00+00:00')
        self.assertEqual(result.status, 'incomplete')
        self.refactor.assert_not_called()
        self.assertFalse((self.repo / '.ai-pilled').exists())
        self.run_at('2026-09-16T03:00:00+00:00')
        path = next((self.repo / '.ai-pilled').glob('nightly-*.json'))
        data = json.loads(path.read_text())
        data['date'] = '9999-12-31'
        path.write_text(json.dumps(data))
        before = path.read_bytes()
        self.refactor.reset_mock()
        result = self.run_at('2026-09-16T04:00:00+00:00')
        self.assertEqual(result.status, 'incomplete')
        self.refactor.assert_not_called()
        self.assertEqual(path.read_bytes(), before)
