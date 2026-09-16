import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.reporting import dashboard, summarize, latest_entries
from ai_pilled.pipeline import PipelineReport
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

    def test_nested_review_success_supersedes_previous_child_failure(self):
        record(self.repo, Report('test', status='fail'), 'test')
        newer = record(self.repo, PipelineReport('staged-review', checks=[
            PipelineReport('quality', checks=[Report('test').to_dict()]).to_dict()]), 'review')
        result = summarize(self.repo)
        self.assertEqual(result['blocker'], 'proceed')
        self.assertEqual(result['counts'], {'pass': 3})
        child = next(entry for entry in result['latest'] if entry['report']['check'] == 'test')
        self.assertEqual(child['at'], newer['at'])
        record(self.repo, Report('test', status='fail'), 'test')
        self.assertEqual(summarize(self.repo)['unresolved'], ['test'])

    def test_nested_failure_is_not_hidden_by_passing_parent(self):
        record(self.repo, PipelineReport('quality', checks=[Report('test', status='fail').to_dict()]), 'quality')
        self.assertEqual(summarize(self.repo)['blocker'], 'wait')
        self.assertEqual(summarize(self.repo)['unresolved'], ['test'])

    def test_nested_steps_and_malformed_or_excessive_children(self):
        latest = latest_entries([{'report': {'check': 'flow', 'status': 'pass',
            'steps': [Report('test', status='fail').to_dict(), Report('test').to_dict()]}}])
        self.assertEqual(latest['test']['report']['status'], 'pass')
        for children in ('invalid', [{}], [Report('test').to_dict()] * 101):
            with self.assertRaises(CommandError):
                latest_entries([{'report': {'check': 'flow', 'status': 'pass', 'checks': children}}])
        with self.assertRaises(CommandError):
            latest_entries([{'report': Report('test').to_dict()}] * 10001)

    def test_incomplete_is_not_success(self):
        missing = Report('coverage')
        missing.add('missing', 'Missing measurement', severity='warning')
        record(self.repo, missing, 'check')
        self.assertEqual(summarize(self.repo)['blocker'], 'wait')

    def test_contradictory_findings_cannot_produce_clean_consumers(self):
        from ai_pilled.suggestions import suggest
        record(self.repo, Report('security'), 'scan')
        output = dashboard(self.repo)
        original = output.read_bytes()
        path = self.repo / '.ai-pilled/events.jsonl'
        for status, severity in (('pass', 'error'), ('pass', 'warning'), ('incomplete', 'error')):
            for nested in (False, True):
                with self.subTest(status=status, severity=severity, nested=nested):
                    report = {'check': 'security', 'status': status,
                              'findings': [{'severity': severity, 'message': 'fixture'}]}
                    if nested:
                        report = {**Report('quality').to_dict(), 'checks': [report]}
                    path.write_text(json.dumps({'at': 'now', 'report': report}) + '\n')
                    for consumer in (summarize, suggest, dashboard):
                        with self.assertRaisesRegex(CommandError, 'contradicts'):
                            consumer(self.repo)
                    self.assertEqual(output.read_bytes(), original)

    def test_invalid_findings_are_rejected_and_legacy_failures_stay_blocked(self):
        for findings in (None, {}, ['invalid'], [{'severity': []}],
                         [{'severity': 'unknown'}], [{'severity': None}], [{'message': 'legacy'}]):
            with self.subTest(findings=findings):
                with self.assertRaises(CommandError):
                    latest_entries([{'report': {'check': 'test', 'status': 'pass', 'findings': findings}}])
        for status, findings in (('pass', [{'severity': 'info'}]),
                                 ('incomplete', [{'severity': 'warning'}]),
                                 ('fail', [{'severity': 'error'}]),
                                 ('fail', [{'message': 'legacy'}]), ('fail', [])):
            report = {'check': 'test', 'status': status, 'findings': findings}
            self.assertEqual(latest_entries([{'report': report}])['test']['report'], report)

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
        with self.assertRaises(CommandError):
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

    def test_dashboard_replacement_preserves_other_hard_links(self):
        import os
        record(self.repo, Report('test'), 'test')
        outside = self.repo / 'keep'
        outside.write_text('untouched')
        path = self.repo / '.ai-pilled' / 'dashboard.html'
        os.link(outside, path)
        dashboard(self.repo)
        self.assertEqual(outside.read_text(), 'untouched')
        self.assertIn('<!doctype html>', path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_dashboard_rejects_named_pipe_without_waiting(self):
        import os
        import subprocess
        import sys
        record(self.repo, Report('test'), 'test')
        os.mkfifo(self.repo / '.ai-pilled' / 'dashboard.html')
        result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo),
                                 'dashboard'], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1], timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertIn('regular file', result.stdout)

    def test_contended_history_lock_returns_bounded_cli_error_and_preserves_file(self):
        record(self.repo, Report('test'), 'test')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes()
        with path.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo),
                                     'summary'], capture_output=True, text=True,
                                    cwd=Path(__file__).resolve().parents[1], timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn('lock is busy', json.loads(result.stdout)['message'])
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(summarize(self.repo)['blocker'], 'proceed')

    def test_contended_writer_does_not_append_or_truncate_history(self):
        record(self.repo, Report('test'), 'test')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes()
        with path.open('rb') as held, patch('ai_pilled.locking.LOCK_TIMEOUT', 0.02):
            fcntl.flock(held, fcntl.LOCK_EX)
            with self.assertRaisesRegex(CommandError, 'lock is busy'):
                record(self.repo, Report('other'), 'blocked')
        self.assertEqual(path.read_bytes(), before)
        record(self.repo, Report('other'), 'after-release')
        self.assertEqual(len(history(self.repo)), 2)

    def test_hard_linked_history_never_changes_the_other_file_or_its_mode(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        outside = self.repo / 'unrelated'
        outside.write_text('preserve this file\n')
        outside.chmod(0o644)
        path = state / 'events.jsonl'
        os.link(outside, path)
        before = outside.read_bytes()
        with self.assertRaisesRegex(CommandError, 'hard link'):
            record(self.repo, Report('test'), 'blocked')
        with self.assertRaisesRegex(CommandError, 'hard link'):
            history(self.repo)
        self.assertEqual(outside.read_bytes(), before)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o644)
        self.assertEqual(path.stat().st_ino, outside.stat().st_ino)

    def test_appended_history_is_private_even_if_existing_mode_was_broadened(self):
        record(self.repo, Report('test'), 'first')
        path = self.repo / '.ai-pilled/events.jsonl'
        path.chmod(0o644)
        record(self.repo, Report('test'), 'second')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([item['event'] for item in history(self.repo)], ['first', 'second'])

    def test_nonfinite_nested_metrics_cannot_corrupt_existing_history(self):
        record(self.repo, Report('valid'), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes()
        for value in (float('nan'), float('inf'), -float('inf')):
            report = Report('invalid')
            report.metrics = {'nested': {'values': [value]}}
            with self.assertRaisesRegex(CommandError, 'finite JSON'):
                record(self.repo, report, 'fixture')
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(len(history(self.repo)), 1)

    def test_history_nesting_boundary_is_checked_before_append(self):
        from ai_pilled.json_data import MAX_NESTING
        for levels, accepted in ((MAX_NESTING - 3, True), (MAX_NESTING - 2, False)):
            value = 0
            for _ in range(levels):
                value = [value]
            report = Report('nested')
            report.metrics = {'value': value}
            if accepted:
                record(self.repo, report, 'fixture')
                self.assertEqual(len(history(self.repo)), 1)
            else:
                path = self.repo / '.ai-pilled/events.jsonl'
                before = path.read_bytes()
                with self.assertRaisesRegex(CommandError, 'history JSON constraints'):
                    record(self.repo, report, 'fixture')
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(len(history(self.repo)), 1)

    def test_keys_that_collide_after_json_encoding_cannot_poison_history(self):
        record(self.repo, Report('valid'), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes()
        report = Report('collision')
        report.metrics = {1: 2, '1': 3}
        with self.assertRaisesRegex(CommandError, 'history JSON constraints'):
            record(self.repo, report, 'fixture')
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(history(self.repo)), 1)

    def test_append_after_complete_record_without_newline_preserves_both_records(self):
        record(self.repo, Report('first'), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes().rstrip(b'\n')
        path.write_bytes(before)
        self.assertEqual(len(history(self.repo)), 1)
        record(self.repo, Report('second'), 'fixture')
        self.assertTrue(path.read_bytes().startswith(before + b'\n'))
        self.assertEqual([entry['report']['check'] for entry in history(self.repo)], ['first', 'second'])

    def test_malformed_partial_history_tail_is_preserved_without_append(self):
        record(self.repo, Report('valid'), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        before = path.read_bytes() + b'{"private-tail":'
        path.write_bytes(before)
        with self.assertRaisesRegex(CommandError, 'incomplete JSON') as raised:
            record(self.repo, Report('second'), 'fixture')
        self.assertNotIn('private-tail', str(raised.exception))
        self.assertEqual(path.read_bytes(), before)

    def test_whitespace_and_carriage_return_tails_keep_record_boundaries(self):
        record(self.repo, Report('first'), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        initial = path.read_bytes().rstrip(b'\n')
        for tail in (b' ', b'\r', b'\r   '):
            with self.subTest(tail=repr(tail)):
                path.write_bytes(initial + tail)
                record(self.repo, Report('second'), 'fixture')
                self.assertEqual([entry['report']['check'] for entry in history(self.repo)], ['first', 'second'])

    def test_unterminated_tail_rotation_keeps_history_within_byte_limit(self):
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 500):
            first = Report('first')
            first.add('note', 'x' * 100, severity='info')
            record(self.repo, first, 'fixture')
            path = self.repo / '.ai-pilled/events.jsonl'
            path.write_bytes(path.read_bytes().rstrip(b'\n'))
            record(self.repo, Report('second'), 'fixture')
            self.assertLessEqual(path.stat().st_size, 500)
            self.assertEqual([entry['report']['check'] for entry in history(self.repo)], ['second'])

    def test_oversized_unterminated_record_is_not_guessed_or_rewritten(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        path = state / 'events.jsonl'
        before = b'"' + b'x' * 501 + b'"'
        path.write_bytes(before)
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', 500):
            with self.assertRaisesRegex(CommandError, 'size limit'):
                record(self.repo, Report('new'), 'fixture')
        self.assertEqual(path.read_bytes(), before)

    def test_rotation_preserves_complete_records_with_carriage_return_separators(self):
        for name in ('first', 'second', 'third'):
            record(self.repo, Report(name), 'fixture')
        path = self.repo / '.ai-pilled/events.jsonl'
        content = path.read_bytes().replace(b'\n', b'\r').rstrip(b'\r')
        path.write_bytes(content)
        maximum = len(content) * 5 // 6
        with patch('ai_pilled.state.MAX_HISTORY_BYTES', maximum):
            record(self.repo, Report('fourth'), 'fixture')
            self.assertLessEqual(path.stat().st_size, maximum)
            self.assertEqual([entry['report']['check'] for entry in history(self.repo)], ['third', 'fourth'])

    def test_history_parent_swap_cannot_append_or_read_outside_evidence(self):
        from ai_pilled.state import directory
        original_symlink = Path.is_symlink
        for operation in ('append', 'read'):
            with self.subTest(operation=operation):
                root = self.repo / operation
                root.mkdir()
                record(root, Report('inside'), 'fixture')
                parent = root / '.ai-pilled'
                outside = root / 'outside'
                outside.mkdir()
                target = outside / 'events.jsonl'
                before = json.dumps({'at': 'now', 'report': Report('outside').to_dict()}) + '\n'
                target.write_text(before)
                target.chmod(0o644)

                def swap(parent=parent, root=root, outside=outside):
                    parent.rename(root / 'original')
                    parent.symlink_to(outside, target_is_directory=True)

                def after_directory(repo):
                    result = directory(repo)
                    swap()
                    return result

                def after_symlink_check(path, selected=parent):
                    result = original_symlink(path)
                    if path == selected:
                        swap()
                    return result

                if operation == 'append':
                    with patch('ai_pilled.state.directory', side_effect=after_directory):
                        with self.assertRaises((CommandError, OSError)):
                            record(root, Report('attempt'), 'fixture')
                else:
                    with patch.object(Path, 'is_symlink', after_symlink_check):
                        with self.assertRaises((CommandError, OSError)):
                            history(root)
                self.assertEqual(target.read_text(), before)
                self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_dashboard_publication_parent_swap_preserves_outside_file(self):
        original_replace = os.replace
        record(self.repo, Report('test'), 'fixture')
        parent = self.repo / '.ai-pilled'
        outside = self.repo / 'outside'
        outside.mkdir()
        target = outside / 'dashboard.html'
        target.write_text('outside must survive')

        def swap(*args, **kwargs):
            parent.rename(self.repo / 'original')
            parent.symlink_to(outside, target_is_directory=True)
            return original_replace(*args, **kwargs)

        with patch('ai_pilled.state.os.replace', side_effect=swap):
            with self.assertRaises((CommandError, OSError)):
                dashboard(self.repo)
        self.assertEqual(target.read_text(), 'outside must survive')
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ['dashboard.html'])
        self.assertEqual(list((self.repo / 'original').glob('.ai-pilled-*.tmp')), [])

    def test_dashboard_uses_one_history_snapshot_during_concurrent_append(self):
        from ai_pilled.reporting import entries
        record(self.repo, Report('security'), 'fixture')

        def append_after_capture(repo):
            captured = entries(repo)
            record(repo, Report('security', status='fail'), 'concurrent failure')
            return captured

        with patch('ai_pilled.reporting.entries', side_effect=append_after_capture) as captured:
            content = dashboard(self.repo).read_text()
        self.assertEqual(captured.call_count, 1)
        self.assertIn('All 1 latest recorded checks passed.', content)
        self.assertIn('<td>pass</td>', content)
        self.assertNotIn('<td>fail</td>', content)
        self.assertEqual(summarize(self.repo)['blocker'], 'wait')
        refreshed = dashboard(self.repo).read_text()
        self.assertIn('1 unresolved result(s)', refreshed)
        self.assertIn('<td>fail</td>', refreshed)
