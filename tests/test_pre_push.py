import os
from unittest.mock import patch
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ai_pilled.git_hooks import install
from ai_pilled.pre_push import pre_push


class PrePushTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='ai-pilled push ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'work'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        self.configure(0)
        self.commit()
        self.remote = Path(self.temp.name) / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(self.remote)], check=True)
        self.git('remote', 'add', 'origin', str(self.remote))

    def git(self, *args, success=True):
        result = subprocess.run(['git', *args], cwd=self.repo, capture_output=True)
        if success and result.returncode:
            self.fail(result.stderr.decode())
        return result

    def configure(self, code):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'commands': {'test': [sys.executable, '-c', f'raise SystemExit({code})']}}))

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'test: fixture')

    def update(self, branch='feature', old=None):
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        return f'refs/heads/feature {head} refs/heads/{branch} {old or "0" * 40}\n'

    def test_actual_push_to_feature_succeeds(self):
        install(self.repo)
        self.git('push', 'origin', 'HEAD:feature')
        remote_head = subprocess.check_output(['git', '--git-dir', str(self.remote),
                                              'rev-parse', 'refs/heads/feature'])
        self.assertEqual(remote_head, self.git('rev-parse', 'HEAD').stdout)

    def test_actual_push_to_protected_branch_fails(self):
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:main', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'protected-branch', result.stdout + result.stderr)

    def test_failed_tests_block_actual_push(self):
        self.configure(1)
        self.commit()
        install(self.repo)
        self.assertNotEqual(self.git('push', 'origin', 'HEAD:feature', success=False).returncode, 0)

    def test_secret_removed_in_later_commit_still_blocks(self):
        (self.repo / 'credential').write_text('ghp_' + 'A' * 36)
        self.commit()
        (self.repo / 'credential').unlink()
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('github-token', [f.rule for f in result.findings])

    def test_dirty_worktree_blocks_false_test_evidence(self):
        (self.repo / 'new.py').write_text('print("uncommitted")')
        result = pre_push(self.repo, self.update())
        self.assertIn('dirty-worktree', [f.rule for f in result.findings])

    def test_non_head_push_cannot_borrow_head_tests(self):
        old = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        (self.repo / 'file').write_text('next')
        self.commit()
        result = pre_push(self.repo, f'old {old} refs/heads/other {"0" * 40}\n')
        self.assertIn('untested-tip', [f.rule for f in result.findings])

    def test_only_outgoing_commits_are_scanned_when_old_tip_is_known(self):
        (self.repo / 'credential').write_text('ghp_' + 'B' * 36)
        self.commit()
        old = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        (self.repo / 'credential').unlink()
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update(old=old)).status, 'pass')

    def test_malformed_input_fails(self):
        self.assertEqual(pre_push(self.repo, 'not valid').status, 'fail')

    def test_test_command_cannot_mutate_files_and_still_authorize_push(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [
            sys.executable, '-c', 'from pathlib import Path; Path("changed.py").write_text("changed")']}}))
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('test-snapshot-changed', [f.rule for f in result.findings])

    def test_test_command_cannot_switch_to_a_new_clean_commit(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [
            'git', 'commit', '--allow-empty', '-qm', 'test: changed head']}}))
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('test-snapshot-changed', [f.rule for f in result.findings])

    def test_outgoing_commit_message_credentials_are_scanned(self):
        self.git('commit', '--allow-empty', '-qm', 'feat: safe subject\n\n' + 'ghp_' + 'A' * 36)
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'github-token' and f.path == '(commit message)' for f in result.findings))

    def test_strict_patterns_check_tip_but_allow_fixed_historical_code(self):
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['aggressiveness'] = 'strict'
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        (self.repo / 'parse.py').write_text('eval(data)\n')
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update()).status, 'fail')
        (self.repo / 'parse.py').write_text('value = 1\n')
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update()).status, 'pass')
