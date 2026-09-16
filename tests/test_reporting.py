from pathlib import Path
import tempfile
import unittest

from ai_pilled.reporting import dashboard, summarize
from ai_pilled.runtime import CommandError, Report
from ai_pilled.state import record


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
