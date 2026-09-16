import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.merging import auto_merge
from ai_pilled.runtime import CommandError, CompletedCommand


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.head = 'a' * 40
        self.pr = {'number': 7, 'state': 'OPEN', 'isDraft': False, 'baseRefName': 'main',
                   'headRefOid': self.head, 'reviewDecision': 'APPROVED', 'mergeable': 'MERGEABLE',
                   'autoMergeRequest': None}
        self.checks = [{'bucket': 'pass'}, {'bucket': 'pending'}]
        self.check_code = None
        self.views = []
        self.calls = []
        fake = patch('ai_pilled.merging.run', side_effect=self.run_gh)
        fake.start()
        self.addCleanup(fake.stop)
        completed = patch('ai_pilled.merging.run_completed', side_effect=self.completed_gh)
        completed.start()
        self.addCleanup(completed.stop)

    def completed_gh(self, argv, cwd, **kwargs):
        stdout = self.run_gh(argv, cwd, **kwargs)
        code = self.check_code
        if code is None:
            code = 8 if any(check.get("bucket") == "pending" for check in self.checks) else 0
        return CompletedCommand(stdout, code)

    def run_gh(self, argv, cwd, **kwargs):
        self.calls.append(argv)
        self.assertNotIn('--admin', argv)
        self.assertNotIn('--delete-branch', argv)
        self.assertEqual(argv[argv.index('--repo') + 1], 'github.com/owner/repo')
        self.assertEqual(kwargs['env']['GH_PROMPT_DISABLED'], '1')
        if argv[2] == 'view':
            return json.dumps(self.views.pop(0) if self.views else self.pr).encode()
        if argv[2] == 'checks':
            self.assertIn('--required', argv)
            return json.dumps(self.checks).encode()
        self.assertEqual(argv[2], 'merge')
        self.assertIn('--auto', argv)
        self.assertIn('--squash', argv)
        self.assertEqual(argv[argv.index('--match-head-commit') + 1], self.head)
        return b''

    def invoke(self, enable=False):
        return auto_merge(self.temp.name, 'owner/repo', 7, 'main', self.head, enable)

    def test_preview_only_reads_and_reports_pending_checks(self):
        result = self.invoke()
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.action, 'preview')
        self.assertEqual(result.metrics['pending_checks'], 1)
        self.assertEqual([args[2] for args in self.calls], ['view', 'checks'])

    def test_check_exit_status_must_match_pending_evidence(self):
        for bucket, code in [('pass', 1), ('pass', 8), ('pending', 0), ('pending', 1)]:
            with self.subTest(bucket=bucket, code=code):
                self.checks = [{'bucket': bucket}]
                self.check_code = code
                result = self.invoke(enable=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'not-requested')
        self.assertNotIn('merge', [args[2] for args in self.calls])

    def test_failed_real_check_process_cannot_preview_or_enable(self):
        from ai_pilled.runtime import run_completed
        executable = Path(self.temp.name) / 'fake-gh'
        executable.write_text(f'#!{sys.executable}\n'
                              "import json\nprint(json.dumps([{'bucket': 'pass'}]))\nraise SystemExit(1)\n")
        executable.chmod(0o755)
        with patch('ai_pilled.merging.run_completed', wraps=run_completed):
            for enable in (False, True):
                result = auto_merge(self.temp.name, 'owner/repo', 7, 'main', self.head,
                                    enable, str(executable))
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'not-requested')
        self.assertNotIn('merge', [args[2] for args in self.calls])

    def test_enable_revalidates_then_confirms_outcome(self):
        enabled = {'mergeMethod': 'SQUASH', 'enabledAt': '2026-09-16T00:00:00Z'}
        for state, request, action in [('OPEN', enabled, 'enabled'), ('MERGED', None, 'merged')]:
            self.views = [self.pr, self.pr, {**self.pr, 'state': state, 'autoMergeRequest': request,
                'mergedAt': '2026-09-16T00:00:00Z', 'mergeCommit': {'oid': 'b' * 40}}]
            self.assertEqual(self.invoke(enable=True).action, action)

    def test_changed_head_before_mutation_blocks_merge(self):
        self.views = [self.pr, {**self.pr, 'headRefOid': 'b' * 40}]
        self.assertEqual(self.invoke(enable=True).status, 'incomplete')
        self.assertNotIn('merge', [args[2] for args in self.calls])

    def test_wrong_base_draft_unapproved_and_unknown_mergeability_block(self):
        for key, value in [('baseRefName', 'wrong'), ('isDraft', True), ('reviewDecision', ''),
                           ('mergeable', 'UNKNOWN'), ('state', 'CLOSED')]:
            self.views = [{**self.pr, key: value}]
            self.assertEqual(self.invoke(enable=True).status, 'incomplete')
        self.assertNotIn('merge', [args[2] for args in self.calls])

    def test_missing_failed_skipped_and_invalid_checks_block(self):
        for checks in [[], [{'bucket': 'fail'}], [{'bucket': 'cancel'}], [{'bucket': 'skipping'}], {}]:
            self.checks = checks
            self.assertEqual(self.invoke(enable=True).status, 'incomplete')
        self.assertNotIn('merge', [args[2] for args in self.calls])

    def test_absent_confirmation_is_not_reported_as_enabled(self):
        result = self.invoke(enable=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'unconfirmed')

    def test_provider_failure_does_not_retry(self):
        with patch('ai_pilled.merging.run', side_effect=CommandError('gh failed')) as run:
            self.assertEqual(self.invoke(enable=True).status, 'incomplete')
            self.assertEqual(run.call_count, 1)

    def test_invalid_selection_never_reaches_provider(self):
        for repo, number, head in [('../x/y', 7, self.head), ('owner/repo', 0, self.head), ('owner/repo', 7, 'short')]:
            self.assertEqual(auto_merge(self.temp.name, repo, number, 'main', head, True).status, 'incomplete')
        self.assertEqual(self.calls, [])

    def test_malformed_or_different_merge_requests_are_unconfirmed(self):
        for request in ({}, {'mergeMethod': 'MERGE', 'enabledAt': '2026-09-16T00:00:00Z'},
                        {'mergeMethod': 'SQUASH', 'enabledAt': True},
                        {'mergeMethod': 'SQUASH', 'enabledAt': '0001-01-01T00:00:00Z'},
                        {'mergeMethod': 'SQUASH', 'enabledAt': '2026-02-30T00:00:00Z'},
                        {'mergeMethod': 'SQUASH', 'enabledAt': '2026-09-16T00:00:00'}):
            with self.subTest(request=request):
                self.views = [self.pr, self.pr, {**self.pr, 'autoMergeRequest': request}]
                result = self.invoke(enable=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'unconfirmed')

    def test_merged_state_requires_commit_and_timestamp_evidence(self):
        for commit, at in ((None, '2026-09-16T00:00:00Z'), ({'oid': 'short'}, '2026-09-16T00:00:00Z'),
                           ({'oid': True}, '2026-09-16T00:00:00Z'), ({'oid': 'b' * 40}, None),
                           ({'oid': 'b' * 40}, {'invalid': 'timestamp'})):
            with self.subTest(commit=commit, at=at):
                self.views = [self.pr, self.pr, {**self.pr, 'state': 'MERGED',
                                               'mergeCommit': commit, 'mergedAt': at}]
                result = self.invoke(enable=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'unconfirmed')

    def test_noninteger_pull_request_identity_is_rejected_before_and_after_action(self):
        for number in (7.0, '7', True):
            self.views = [{**self.pr, 'number': number}]
            self.assertEqual(self.invoke(enable=True).action, 'not-requested')
            self.views = [self.pr, self.pr, {**self.pr, 'number': number, 'state': 'MERGED'}]
            self.assertEqual(self.invoke(enable=True).action, 'unconfirmed')
