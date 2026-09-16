import os
from unittest.mock import patch
from pathlib import Path
import subprocess
import tempfile
import unittest

from ai_pilled.git_hooks import install, uninstall
from ai_pilled.runtime import CommandError


class GitHookTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='ai-pilled hooks ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        self.git('add', '.gitignore')

    def git(self, *args, success=True):
        result = subprocess.run(['git', *args], cwd=self.repo, capture_output=True)
        if success and result.returncode:
            self.fail(result.stderr.decode())
        return result

    def test_real_git_commit_blocks_secret(self):
        install(self.repo)
        (self.repo / 'secret.txt').write_text('ghp_' + 'A' * 36)
        self.git('add', 'secret.txt')
        result = self.git('commit', '-m', 'feat: add credential', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'github-token', result.stdout + result.stderr)

    def test_real_git_commit_validates_message(self):
        install(self.repo)
        self.assertNotEqual(self.git('commit', '-m', 'oops', success=False).returncode, 0)
        self.git('commit', '-m', 'chore: initialize project')

    def test_install_twice_and_uninstall_restore_default(self):
        install(self.repo)
        install(self.repo)
        uninstall(self.repo)
        uninstall(self.repo)
        self.git('commit', '-m', 'ordinary message allowed after uninstall')
        install(self.repo)

    def test_existing_hook_is_preserved(self):
        hook = self.repo / '.git' / 'hooks' / 'pre-commit'
        hook.write_text('#!/bin/sh\nexit 0\n')
        hook.chmod(0o755)
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertEqual(hook.read_text(), '#!/bin/sh\nexit 0\n')

    def test_existing_hook_manager_is_preserved(self):
        self.git('config', 'core.hooksPath', 'custom-hooks')
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertEqual(self.git('config', '--get', 'core.hooksPath').stdout.strip(), b'custom-hooks')

    def test_changed_configuration_not_overwritten_on_uninstall(self):
        install(self.repo)
        self.git('config', 'core.hooksPath', 'new-hooks')
        with self.assertRaises(CommandError):
            uninstall(self.repo)

    def test_linked_worktree_does_not_change_primary_hooks(self):
        self.git('commit', '-m', 'chore: initialize')
        linked = self.repo / 'linked'
        self.git('worktree', 'add', '-b', 'feature', str(linked))
        install(linked)
        self.assertNotEqual(self.git('config', '--get', 'core.hooksPath', success=False).returncode, 0)
        value = subprocess.check_output(['git', 'config', '--get', 'core.hooksPath'], cwd=linked)
        self.assertEqual(value.decode().strip(), str(linked / '.ai-pilled' / 'hooks'))
        uninstall(linked)

    def test_modified_generated_hook_is_preserved(self):
        install(self.repo)
        path = self.repo / '.ai-pilled' / 'hooks' / 'pre-commit'
        path.write_text(path.read_text() + '# user change\n')
        with self.assertRaises(CommandError):
            uninstall(self.repo)
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertIn('user change', path.read_text())

    def test_symlink_installation_directory_rejected(self):
        outside = self.repo / 'outside'
        outside.mkdir()
        (self.repo / '.ai-pilled').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertEqual(list(outside.iterdir()), [])
