import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.pipeline import quality
from ai_pilled.reporting import summarize


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


    def test_unscannable_file_created_by_check_blocks_quality(self):
        self.configure(test=[sys.executable, '-c',
                             'from pathlib import Path; Path("new-link").symlink_to(".gitignore")'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(any(f.rule == 'security:scan-incomplete' for f in result.findings))

    def test_secret_created_by_check_is_reported_as_failure(self):
        self.configure(test=[sys.executable, '-c',
                             'from pathlib import Path; Path("new-secret").write_text("ghp_" + "Z" * 36)'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == 'new-secret' for f in result.findings))
        self.assertIn('security', summarize(self.repo)['unresolved'])


    def test_strict_final_scan_reports_new_unsafe_python(self):
        commands = {name: [sys.executable, '-c', 'pass']
                    for name in ('lint', 'typecheck', 'deadcode', 'coverage')}
        commands['test'] = [sys.executable, '-c',
                            'from pathlib import Path; Path("unsafe.py").write_text("eval(input())")']
        self.configure('strict', **commands)
        result = quality(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == 'unsafe.py' for f in result.findings))


    def test_permission_only_change_invalidates_quality(self):
        self.configure(test=[sys.executable, '-c',
                             'from pathlib import Path; Path(".gitignore").chmod(0o755)'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('snapshot-changed', [f.rule for f in result.findings])

    def test_index_only_change_invalidates_quality(self):
        self.configure(test=[sys.executable, '-c',
                             'import subprocess; subprocess.run(["git", "update-index", '
                             '"--chmod=+x", ".gitignore"], check=True)'])
        result = quality(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('snapshot-changed', [f.rule for f in result.findings])
