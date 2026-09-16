import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.healing import heal


class HealingTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / 'code.py').write_text('value = 1\n')
        self.config = {'aggressiveness': 'lazy', 'commands': {'test': [sys.executable, '-c',
            'from pathlib import Path; assert Path("code.py").read_text() == "value = 1\\n"']}}
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))
        self.git('add', '.gitignore', 'code.py', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: good baseline')
        self.good = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'code.py').write_text('value = 2\n')
        self.git('add', 'code.py')
        self.git('commit', '-qm', 'feat: introduce regression')
        self.bad = self.git('rev-parse', 'HEAD').decode().strip()

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def test_default_exports_verified_patch_and_preserves_source(self):
        result = heal(self.repo, self.bad)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.action, 'preview')
        self.assertEqual([c['status'] for c in result.checks], ['fail', 'pass', 'fail'])
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), self.bad)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        self.git('apply', '--check', result.patch)
        self.git('apply', result.patch)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 1\n')

    def test_apply_creates_revert_commit_without_rewriting_history(self):
        hook = self.repo / '.git' / 'hooks' / 'commit-msg'
        hook.write_text('#!/bin/sh\ngrep -q "^fix: revert failing commit " "$1"\n')
        hook.chmod(0o755)
        result = heal(self.repo, self.bad, apply=True)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.action, 'applied')
        self.assertEqual(self.git('rev-parse', 'HEAD^').decode().strip(), self.bad)
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), self.git('rev-parse', self.good + '^{tree}'))
        self.assertEqual(self.git('status', '--porcelain'), b'')

    def test_stale_head_and_dirty_worktree_are_rejected(self):
        self.assertEqual(heal(self.repo, self.good, apply=True).status, 'incomplete')
        (self.repo / 'code.py').write_text('uncommitted')
        self.assertEqual(heal(self.repo, self.bad, apply=True).status, 'incomplete')
        self.assertEqual((self.repo / 'code.py').read_text(), 'uncommitted')

    def test_policy_reversal_requires_manual_review(self):
        self.config['timeout'] = 60
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))
        self.git('add', '.ai-pilled.json')
        self.git('commit', '-qm', 'chore: alter policy')
        result = heal(self.repo, self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('quality policy', result.findings[0].message)

    def test_still_broken_parent_does_not_generate_patch(self):
        (self.repo / 'code.py').write_text('value = 3\n')
        self.git('add', 'code.py')
        self.git('commit', '-qm', 'feat: another regression')
        result = heal(self.repo, self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual(result.status, 'fail')
        self.assertFalse(result.patch)

    def test_passing_current_tests_do_not_revert(self):
        (self.repo / 'code.py').write_text('value = 1\n')
        self.git('add', 'code.py')
        self.git('commit', '-qm', 'fix: restore behavior')
        result = heal(self.repo, self.git('rev-parse', 'HEAD').decode().strip(), apply=True)
        self.assertEqual(result.action, 'unnecessary')
        self.assertFalse(result.patch)

    def test_rejected_commit_requires_checkout_inspection_without_reset(self):
        hook = self.repo / '.git' / 'hooks' / 'pre-commit'
        hook.write_text('#!/bin/sh\nexit 1\n')
        hook.chmod(0o755)
        result = heal(self.repo, self.bad, apply=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'inspect-checkout')
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), self.bad)
        self.assertTrue(self.git('diff', '--cached'))

    def test_unavailable_tests_are_not_evidence_for_a_revert(self):
        self.config['commands']['test'] = ['missing-ai-pilled-test-executable']
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))
        self.git('add', '.ai-pilled.json')
        self.git('commit', '-qm', 'chore: unavailable tool')
        head = self.git('rev-parse', 'HEAD').decode().strip()
        result = heal(self.repo, head, apply=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.checks[0]['status'], 'incomplete')
        self.assertFalse(result.patch)
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), head)


    def test_failure_that_no_longer_reproduces_never_creates_revert(self):
        from ai_pilled.runtime import Report
        failed = Report('test')
        failed.add('command-failed', 'Test failed')
        with patch('ai_pilled.healing.command_check', side_effect=[failed, Report('test')]):
            result = heal(self.repo, self.bad, apply=True)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.action, 'unnecessary')
        self.assertFalse(result.patch)
        self.assertFalse(result.commit)
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), self.bad)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        self.assertEqual(result.findings[0].rule, 'failure-not-reproduced')

    def test_unavailable_confirmation_never_creates_revert(self):
        from ai_pilled.runtime import Report
        failed = Report('test')
        failed.add('command-failed', 'Test failed')
        unavailable = Report('test')
        unavailable.add('command-unavailable', 'Test timed out', severity='warning')
        with patch('ai_pilled.healing.command_check', side_effect=[failed, unavailable]):
            result = heal(self.repo, self.bad, apply=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.patch)
        self.assertFalse(result.commit)
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), self.bad)
