import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.runtime import Report
from ai_pilled.staged_review import review_checks


class StagedReviewTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q', '-b', 'feature')
        self.commands = {name: [sys.executable, '-c', 'pass']
                         for name in ('test', 'lint', 'typecheck', 'deadcode', 'coverage')}
        self.configure()
        (self.repo / 'source.py').write_text('value = 1\n')
        self.git('add', '.ai-pilled.json', 'source.py')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def configure(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'aggressiveness': 'lazy',
                                                              'commands': self.commands}))
        self.git('add', '.ai-pilled.json')

    def test_all_checks_required_even_for_lazy_profile(self):
        result = review_checks(self.repo)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(len(result.checks[1]['checks']), 6)
        self.commands.pop('lint')
        self.configure()
        self.assertEqual(review_checks(self.repo).status, 'incomplete')

    def test_unstaged_fix_cannot_hide_staged_defect(self):
        self.commands['test'] = [sys.executable, '-c',
                                'from pathlib import Path; assert "value = 2" in Path("source.py").read_text()']
        self.configure()
        (self.repo / 'source.py').write_text('value = 2\n')
        result = review_checks(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual((self.repo / 'source.py').read_text(), 'value = 2\n')

    def test_tracked_executable_uses_staged_version(self):
        script = self.repo / 'check'
        script.write_text(f'#!{sys.executable}\nraise SystemExit(1)\n')
        script.chmod(0o755)
        self.git('add', 'check')
        script.write_text(f'#!{sys.executable}\npass\n')
        self.commands['test'] = ['./check']
        self.configure()
        self.assertEqual(review_checks(self.repo).status, 'fail')

    def test_untracked_tool_fallback_and_git_routing_isolation(self):
        tools = self.repo / '.ai-pilled/tools'
        tools.mkdir(parents=True)
        exe = tools / 'check'
        exe.write_text(f'#!{sys.executable}\npass\n')
        exe.chmod(0o755)
        self.commands['lint'] = ['.ai-pilled/tools/check']
        self.configure()
        before = self.git('ls-files', '--stage')
        with patch.dict(os.environ, {'GIT_DIR': str(self.repo / '.git'), 'GIT_WORK_TREE': str(self.repo)}):
            self.assertEqual(review_checks(self.repo).status, 'pass')
        self.assertEqual(self.git('ls-files', '--stage'), before)

    def test_mutation_stays_in_snapshot_and_invalidates_checks(self):
        self.commands['test'] = [sys.executable, '-c',
                                'from pathlib import Path; Path("source.py").write_text("value = 9")']
        self.configure()
        self.assertEqual(review_checks(self.repo).status, 'incomplete')
        self.assertEqual((self.repo / 'source.py').read_text(), 'value = 1\n')

    def test_secret_prevents_commands_and_model(self):
        (self.repo / 'secret').write_text('ghp_' + 'A' * 36)
        self.git('add', 'secret')
        with patch('ai_pilled.staged_review.quality') as check, patch('ai_pilled.staged_review.review') as model:
            self.assertEqual(review_checks(self.repo, model=True).status, 'fail')
            check.assert_not_called()
            model.assert_not_called()

    def test_missing_checks_prevent_model_call(self):
        self.commands.pop('lint')
        self.configure()
        with patch('ai_pilled.staged_review.review') as model:
            self.assertEqual(review_checks(self.repo, model=True).status, 'incomplete')
            model.assert_not_called()

    def test_index_change_during_checks_invalidates_evidence(self):
        def changed(*args, **kwargs):
            (self.repo / 'source.py').write_text('value = 3\n')
            self.git('add', 'source.py')
            return Report('quality')
        with patch('ai_pilled.staged_review.quality', side_effect=changed):
            self.assertEqual(review_checks(self.repo).status, 'incomplete')

    def test_model_must_review_same_index(self):
        from ai_pilled.security import scan
        result = Report('codex-review', snapshot=scan(self.repo).snapshot)
        with patch('ai_pilled.staged_review.review', return_value=result) as model:
            self.assertEqual(review_checks(self.repo, model=True).status, 'pass')
            model.assert_called_once()
        result.snapshot = 'different'
        with patch('ai_pilled.staged_review.review', return_value=result):
            self.assertEqual(review_checks(self.repo, model=True).status, 'incomplete')
