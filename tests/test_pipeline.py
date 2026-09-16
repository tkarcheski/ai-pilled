import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.pipeline import quality


class PipelineTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        self.configure()
        self.commit()

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def configure(self, profile='normal', **commands):
        values = {'test': [sys.executable, '-c', 'pass']} | commands
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'aggressiveness': profile, 'commands': values}))

    def commit(self):
        self.git('add', '.gitignore', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: fixture')

    def test_ready_passes_only_clean_feature_branch(self):
        self.assertEqual(quality(self.repo, ready=True).status, 'pass')
        (self.repo / 'dirty').write_text('change')
        result = quality(self.repo, ready=True)
        self.assertEqual(result.status, 'fail')
        self.assertIn('dirty-worktree', [f.rule for f in result.findings])

    def test_protected_and_detached_branches_block_readiness(self):
        self.git('branch', '-m', 'main')
        self.assertIn('protected-branch', [f.rule for f in quality(self.repo, True).findings])
        self.git('checkout', '--detach', '-q')
        self.assertIn('detached-head', [f.rule for f in quality(self.repo, True).findings])

    def test_normal_runs_configured_checks_and_preserves_failure(self):
        self.configure(lint=[sys.executable, '-c', 'raise SystemExit(1)'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual([c['check'] for c in result.checks], ['security', 'test', 'lint'])
        self.assertEqual(result.metrics['checks_passed'], 2)

    def test_lazy_runs_tests_but_omits_extra_checks(self):
        self.configure('lazy', lint=['not-installed'])
        self.assertEqual(quality(self.repo).status, 'pass')

    def test_strict_missing_tools_are_incomplete_not_pass(self):
        self.configure('strict')
        result = quality(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual({c['check'] for c in result.checks},
                         {'security', 'test', 'lint', 'typecheck', 'deadcode', 'coverage'})

    def test_secret_stops_execution_of_configured_commands(self):
        (self.repo / 'secret').write_text('ghp_' + 'A' * 36)
        with patch('ai_pilled.pipeline.command_check') as check:
            self.assertEqual(quality(self.repo).status, 'fail')
            check.assert_not_called()

    def test_mutating_check_invalidates_quality_evidence(self):
        self.configure(test=[sys.executable, '-c',
                             'from pathlib import Path; Path("changed").write_text("new")'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('snapshot-changed', [f.rule for f in result.findings])

    def test_npm_lock_dispatches_audit_once_in_normal_profile(self):
        from ai_pilled.runtime import Report
        (self.repo / 'package-lock.json').write_text('{}')
        with patch('ai_pilled.pipeline.audit', return_value=Report('dependency-vulnerabilities')) as audit:
            result = quality(self.repo)
            self.assertEqual(result.status, 'pass')
            audit.assert_called_once_with(self.repo)
