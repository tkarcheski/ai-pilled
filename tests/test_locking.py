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

    def test_replaced_state_parent_cannot_redirect_lock_creation(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        for module, helper in ((git_hooks, 'state_directory'), (codex_hooks, 'directory')):
            with self.subTest(installer=module.__name__), tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary) / 'repo'
                outside = Path(temporary) / 'outside'
                repo.mkdir()
                outside.mkdir()
                original = getattr(module, helper)

                def swap(root, original=original, outside=outside):
                    state = original(root)
                    state.rename(root / 'parked-state')
                    state.symlink_to(outside, target_is_directory=True)
                    return state

                with patch.dict(os.environ, env, clear=True):
                    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
                    with patch.object(module, helper, side_effect=swap):
                        with self.assertRaises((CommandError, OSError)):
                            with module.locked(repo):
                                pass
                self.assertEqual(list(outside.iterdir()), [])
