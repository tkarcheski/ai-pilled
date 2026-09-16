import os
import json
import sys
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

    def test_nonregular_installation_inputs_preserve_hooks_and_configuration(self):
        install(self.repo)
        state = self.repo / '.ai-pilled'
        hooks = state / 'hooks'
        configured = self.git('config', '--get', 'core.hooksPath').stdout
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                   PYTHONDONTWRITEBYTECODE='1')
        for path in (state / 'installation.json', hooks / 'pre-commit'):
            original, mode = path.read_bytes(), path.stat().st_mode & 0o777
            for kind in ('fifo', 'oversized'):
                with self.subTest(path=path.name, kind=kind):
                    path.unlink()
                    if kind == 'fifo':
                        os.mkfifo(path)
                    else:
                        path.write_bytes(b'x' * 64_001)
                    try:
                        for command in ('install-git-hooks', 'uninstall-git-hooks'):
                            result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo',
                                                     str(self.repo), command], env=env,
                                                    capture_output=True, timeout=3, check=False)
                            self.assertEqual(result.returncode, 2)
                            self.assertEqual(json.loads(result.stdout)['status'], 'error')
                            self.assertEqual(self.git('config', '--get', 'core.hooksPath').stdout, configured)
                            self.assertTrue((hooks / 'commit-msg').is_file())
                        if kind == 'fifo':
                            self.assertTrue(path.is_fifo())
                        else:
                            self.assertEqual(path.stat().st_size, 64_001)
                    finally:
                        path.unlink()
                        path.write_bytes(original)
                        path.chmod(mode)

    def test_commit_message_special_and_oversized_files_fail_promptly(self):
        path = self.repo / 'message'
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                   PYTHONDONTWRITEBYTECODE='1')
        for kind in ('fifo', 'oversized'):
            with self.subTest(kind=kind):
                if kind == 'fifo':
                    os.mkfifo(path)
                else:
                    path.write_bytes(b'x' * 64_001)
                result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo),
                                         'hook', 'commit-msg', str(path)], env=env,
                                        capture_output=True, timeout=3, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)['status'], 'error')
                path.unlink()

    def test_configuration_values_preserve_empty_and_trailing_newlines(self):
        from ai_pilled.git_hooks import git_value
        self.assertIsNone(git_value(self.repo, 'probe.missing'))
        for value in ('', 'trailing\n', 'multiple\n\n'):
            self.git('config', 'probe.value', value)
            self.assertEqual(git_value(self.repo, 'probe.value'), value)
            self.assertEqual(git_value(self.repo, 'probe.value', scope=None), value)

    def test_configuration_reads_are_bounded_and_errors_are_not_absence(self):
        from ai_pilled.git_hooks import git_value
        with (self.repo / '.git/config').open('a') as stream:
            stream.write('[probe]\n value = ' + 'x' * 20_000 + '\n')
        with self.assertRaises(CommandError):
            git_value(self.repo, 'probe.value')
        (self.repo / '.git/config').write_text('[invalid config')
        with self.assertRaises(CommandError):
            git_value(self.repo, 'probe.value')

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

    def test_reinstall_preflights_all_hooks_before_repair(self):
        install(self.repo)
        hooks = self.repo / '.ai-pilled' / 'hooks'
        (hooks / 'pre-commit').unlink()
        (hooks / 'pre-push').write_text('user replacement')
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertFalse((hooks / 'pre-commit').exists())
        self.assertEqual((hooks / 'pre-push').read_text(), 'user replacement')

    def test_missing_checksums_never_authorize_removal(self):
        import json
        install(self.repo)
        manifest = self.repo / '.ai-pilled' / 'installation.json'
        data = json.loads(manifest.read_text())
        data['hashes'] = {}
        manifest.write_text(json.dumps(data))
        hook = self.repo / '.ai-pilled' / 'hooks' / 'pre-commit'
        hook.write_text(hook.read_text() + '# user edit\n')
        for operation in (uninstall, install):
            with self.assertRaises(CommandError):
                operation(self.repo)
        self.assertIn('user edit', hook.read_text())
        self.assertTrue(manifest.exists())

    def test_git_config_failure_rolls_back_new_install(self):
        from ai_pilled.runtime import run
        def fail_config(argv, *args, **kwargs):
            if argv[:3] == ['git', 'config', '--local']:
                raise CommandError('simulated config failure')
            return run(argv, *args, **kwargs)
        with patch('ai_pilled.git_hooks.run', side_effect=fail_config):
            with self.assertRaises(CommandError):
                install(self.repo)
        self.assertFalse((self.repo / '.ai-pilled' / 'hooks').exists())
        self.assertFalse((self.repo / '.ai-pilled' / 'installation.json').exists())
        install(self.repo)

    def test_commit_hook_runs_opted_in_model_review_and_blocks_missing_cli(self):
        import json
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'review_on_commit': True, 'codex_executable': 'missing-ai-pilled-codex'}))
        self.git('add', '.ai-pilled.json')
        install(self.repo)
        result = self.git('commit', '-m', 'feat: enforce reviews', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'review-unavailable', result.stdout + result.stderr)

    def test_commit_body_credentials_are_rejected(self):
        install(self.repo)
        result = self.git('commit', '-m', 'feat: safe subject', '-m', 'ghp_' + 'A' * 36, success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'github-token', result.stdout + result.stderr)

    def test_commit_hook_accepts_a_structured_review_of_the_message(self):
        import json
        import sys
        install(self.repo)
        provider = self.repo / '.ai-pilled' / 'fake-reviewer'
        provider.write_text(f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\n'
                            'assert b"feat: reviewed change" in sys.stdin.buffer.read()\n'
                            'Path(sys.argv[sys.argv.index("--output-last-message")+1]).write_text(\'{"findings": []}\')\n')
        provider.chmod(0o755)
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'review_on_commit': True, 'codex_executable': str(provider)}))
        self.git('add', '.ai-pilled.json')
        self.git('commit', '-m', 'feat: reviewed change')


    def test_forged_checksums_cannot_authorize_deleting_user_hooks(self):
        import hashlib
        import json
        install(self.repo)
        manifest = self.repo / '.ai-pilled' / 'installation.json'
        hook = self.repo / '.ai-pilled' / 'hooks' / 'pre-commit'
        hook.write_text('#!/bin/sh\n# Replacement user hook\nexit 0\n')
        data = json.loads(manifest.read_text())
        data['hashes']['pre-commit'] = hashlib.sha256(hook.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(data))
        for operation in (uninstall, install):
            with self.assertRaises(CommandError):
                operation(self.repo)
        self.assertIn('Replacement user hook', hook.read_text())
        self.assertEqual(self.git('config', '--get', 'core.hooksPath').stdout.decode().strip(), str(hook.parent))

    def test_manifest_cannot_restore_an_unrelated_hook_manager(self):
        import json
        install(self.repo)
        manifest = self.repo / '.ai-pilled' / 'installation.json'
        data = json.loads(manifest.read_text())
        data['previous'] = 'unrelated-hooks'
        manifest.write_text(json.dumps(data))
        with self.assertRaises(CommandError):
            uninstall(self.repo)
        self.assertNotEqual(self.git('config', '--get', 'core.hooksPath').stdout.strip(), b'unrelated-hooks')
        self.assertTrue((self.repo / '.ai-pilled' / 'hooks' / 'pre-commit').exists())


    def test_concurrent_installers_leave_one_complete_owned_installation(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: install(self.repo), range(6)))
        self.assertTrue(all(result.status == 'pass' for result in results))
        hooks = self.repo / '.ai-pilled' / 'hooks'
        self.assertTrue(all((hooks / event).is_file() for event in ('pre-commit', 'commit-msg', 'pre-push')))
        self.git('commit', '-m', 'test: concurrent setup remains usable')
        uninstall(self.repo)
        self.assertFalse(hooks.exists())


    def test_concurrent_uninstallers_preserve_consistent_configuration(self):
        from concurrent.futures import ThreadPoolExecutor
        install(self.repo)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: uninstall(self.repo), range(6)))
        self.assertTrue(all(result.status == 'pass' for result in results))
        self.assertFalse((self.repo / '.ai-pilled' / 'hooks').exists())
        self.assertEqual(self.git('config', '--get', 'core.hooksPath', success=False).returncode, 1)

    def test_comprehensive_commit_checks_block_partially_staged_defect(self):
        import json
        import sys
        commands = {name: [sys.executable, '-c', 'pass']
                    for name in ('lint', 'typecheck', 'deadcode', 'coverage')}
        commands['test'] = [sys.executable, 'check.py']
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'review_checks_on_commit': True, 'commands': commands}))
        (self.repo / 'check.py').write_text('raise SystemExit(1)\n')
        self.git('add', '.ai-pilled.json', 'check.py')
        (self.repo / 'check.py').write_text('pass\n')
        install(self.repo)
        result = self.git('commit', '-m', 'feat: broken staged test', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'command-failed', result.stdout + result.stderr)
        self.assertNotEqual(self.git('rev-parse', '--verify', 'HEAD', success=False).returncode, 0)
        self.git('add', 'check.py')
        self.git('commit', '-m', 'feat: fixed staged test')
