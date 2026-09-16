import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled import codex_hooks, git_hooks
from ai_pilled.runtime import CommandError


class InstallationLockTests(unittest.TestCase):
    def test_contended_installers_preserve_configuration_and_owned_files(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, env, clear=True):
            repo = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            state = repo / '.ai-pilled'
            state.mkdir()
            for module, name in ((git_hooks, 'git-install.lock'), (codex_hooks, 'codex-install.lock')):
                with self.subTest(installer=name):
                    before = (repo / '.git/config').read_bytes()
                    path = state / name
                    with path.open('w') as held, patch('ai_pilled.locking.LOCK_TIMEOUT', 0.02):
                        fcntl.flock(held, fcntl.LOCK_EX)
                        with self.assertRaisesRegex(CommandError, 'lock is busy'):
                            with module.locked(repo):
                                self.fail('Contended installer must not enter its mutation section')
                    self.assertEqual((repo / '.git/config').read_bytes(), before)
                    self.assertTrue(path.is_file())
                    self.assertFalse((repo / '.codex').exists())
                    self.assertFalse((state / 'hooks').exists())
