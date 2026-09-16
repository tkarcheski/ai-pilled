from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.reporting import dashboard, summarize
from ai_pilled.runtime import CommandError, Report
from ai_pilled.state import history, record


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def test_no_history_is_not_clean_evidence(self):
        result = summarize(self.repo)
        self.assertEqual(result['blocker'], 'wait')
        self.assertIsNone(result['last_recorded_at'])

    def test_latest_failure_blocks_until_same_check_passes(self):
        failed = Report('test')
        failed.add('failure', 'Tests failed')
        record(self.repo, failed, 'check')
        record(self.repo, Report('security'), 'scan')
        self.assertEqual(summarize(self.repo)['unresolved'], ['test'])
        record(self.repo, Report('test'), 'check')
        result = summarize(self.repo)
        self.assertEqual(result['blocker'], 'proceed')
        self.assertEqual(result['counts'], {'pass': 2})
        self.assertIn('does not validate current files', result['evidence'])

    def test_incomplete_is_not_success(self):
        missing = Report('coverage')
        missing.add('missing', 'Missing measurement', severity='warning')
        record(self.repo, missing, 'check')
        self.assertEqual(summarize(self.repo)['blocker'], 'wait')

    def test_dashboard_escapes_untrusted_findings(self):
        report = Report('<script>alert(1)</script>')
        report.add('test', '</td><script>alert(2)</script>')
        report.metrics = {'coverage_percent': 86.5, '<script>': '<img src=x>'}
        record(self.repo, report, 'test')
        content = dashboard(self.repo).read_text()
        self.assertNotIn('<script>', content)
        self.assertIn('&lt;script&gt;', content)
        self.assertIn('Content-Security-Policy', content)
        self.assertIn('Historical results only', content)
        self.assertIn('coverage_percent', content)
        self.assertIn('86.5', content)
        self.assertNotIn('<img src=x>', content)

    def test_dashboard_does_not_follow_symlink(self):
        record(self.repo, Report('test'), 'test')
        outside = self.repo / 'keep'
        outside.write_text('untouched')
        (self.repo / '.ai-pilled' / 'dashboard.html').symlink_to(outside)
        with self.assertRaises(OSError):
            dashboard(self.repo)
        self.assertEqual(outside.read_text(), 'untouched')

    def test_corrupt_history_is_explicit_error(self):
        path = self.repo / '.ai-pilled'
        path.mkdir()
        for value in ('not json', '[]', '{"report":{}}'):
            (path / 'events.jsonl').write_text(value + '\n')
            with self.assertRaises(CommandError):
                summarize(self.repo)


    def test_rotation_enforces_byte_budget_and_preserves_latest_record(self):
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 1400):
            for index in range(10):
                result = Report('test')
                result.add('failure', 'detail ' * 70)
                entry = record(self.repo, result, str(index))
                path = self.repo / '.ai-pilled' / 'events.jsonl'
                self.assertLessEqual(path.stat().st_size, 1400)
                self.assertEqual(history(self.repo)[-1]['id'], entry['id'])
            self.assertEqual(summarize(self.repo)['blocker'], 'wait')

    def test_oversized_record_does_not_change_existing_history(self):
        record(self.repo, Report('test'), 'test')
        path = self.repo / '.ai-pilled' / 'events.jsonl'
        original = path.read_bytes()
        result = Report('test')
        result.add('large', 'x' * 2000)
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 1400):
            with self.assertRaises(CommandError):
                record(self.repo, result, 'test')
        self.assertEqual(path.read_bytes(), original)

    def test_oversized_history_read_is_explicitly_incomplete(self):
        record(self.repo, Report('test'), 'test')
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 10):
            with self.assertRaises(CommandError):
                summarize(self.repo)

    def test_legacy_oversized_history_rotates_using_complete_records(self):
        for index in range(20):
            record(self.repo, Report('test'), str(index))
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 1400):
            latest = record(self.repo, Report('test'), 'latest')
            self.assertEqual(history(self.repo)[-1]['id'], latest['id'])
            self.assertLessEqual((self.repo / '.ai-pilled' / 'events.jsonl').stat().st_size, 1400)


    def test_excessively_nested_history_is_an_explicit_error(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        nested = '[' * 150 + '0' + ']' * 150
        (state / 'events.jsonl').write_text('{"at":"now","report":{"check":"test",'
            '"status":"pass","findings":[],"metrics":{"nested":' + nested + '}}}\n')
        with self.assertRaises(CommandError):
            summarize(self.repo)
