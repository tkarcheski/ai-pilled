import json
import shlex
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.codex_hooks import install, uninstall
from ai_pilled.runtime import CommandError


class CodexInstallTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='codex hooks ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / '.codex').mkdir()
        self.path = self.repo / '.codex' / 'hooks.json'
        self.original = {'description': 'user hooks', 'hooks': {'SessionStart': [
            {'hooks': [{'type': 'command', 'command': 'echo existing'}]}]}}
        self.path.write_text(json.dumps(self.original))

    def test_publication_rejects_replaced_configuration_parent(self):
        from ai_pilled.state import atomic_text
        for removing in (False, True):
            with self.subTest(removing=removing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / 'repo'
                outside = Path(folder) / 'outside'
                root.mkdir()
                outside.mkdir()
                subprocess.run(['git', 'init', '-q', str(root)], check=True)
                (root / '.codex').mkdir()
                if removing:
                    install(root)
                path = root / '.codex' / 'hooks.json'
                original = path.read_bytes() if path.exists() else None

                def publish(target, text, *args, fixture_root=root, outside=outside, path=path, **kwargs):
                    if target == path:
                        (fixture_root / '.codex').rename(fixture_root / 'parked-codex')
                        (fixture_root / '.codex').symlink_to(outside, target_is_directory=True)
                    return atomic_text(target, text, *args, **kwargs)

                with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
                    with self.assertRaises((CommandError, OSError)):
                        (uninstall if removing else install)(root)
                self.assertEqual(list(outside.iterdir()), [])
                parked = root / 'parked-codex' / 'hooks.json'
                self.assertEqual(parked.read_bytes() if parked.exists() else None, original)

    def test_snapshot_rejects_changes_after_descriptor_read(self):
        from contextlib import contextmanager
        from ai_pilled.codex_hooks import read_snapshot
        original = os.fdopen
        for change in ('replace', 'delete', 'mode'):
            with self.subTest(change=change):
                self.path.write_text(json.dumps(self.original))
                self.path.chmod(0o644)
                changed = []

                @contextmanager
                def opened(*args, change=change, changed=changed, **kwargs):
                    with original(*args, **kwargs) as stream:
                        yield stream
                    if not changed:
                        changed.append(True)
                        if change == 'replace':
                            replacement = self.repo / 'replacement.json'
                            replacement.write_text('{}')
                            replacement.replace(self.path)
                        elif change == 'delete':
                            self.path.unlink()
                        else:
                            self.path.chmod(0o600)

                with patch.object(os, 'fdopen', side_effect=opened):
                    with self.assertRaises(CommandError):
                        read_snapshot(self.path, self.repo)

    def test_snapshot_rejects_symlink_parent(self):
        from ai_pilled.codex_hooks import read_snapshot
        parent = self.repo / '.codex'
        parked = self.repo / 'parked-codex'
        parent.rename(parked)
        parent.symlink_to(parked, target_is_directory=True)
        with self.assertRaises(CommandError):
            read_snapshot(self.path, self.repo)
        self.assertEqual(json.loads((parked / 'hooks.json').read_text()), self.original)

    def test_manifest_cleanup_cannot_follow_replaced_parent(self):
        from ai_pilled import codex_hooks
        for removing in (False, True):
            with self.subTest(removing=removing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / 'repo'
                outside = Path(folder) / 'outside'
                root.mkdir()
                outside.mkdir()
                subprocess.run(['git', 'init', '-q', str(root)], check=True)
                if removing:
                    install(root)
                manifest = root / '.ai-pilled' / 'codex-installation.json'
                target = outside / manifest.name
                target.write_text('outside sentinel')
                original_check = codex_hooks.require_unchanged
                original_write = codex_hooks.atomic_text
                checks = []

                def checked(path, *args, root=root, outside=outside, manifest=manifest,
                            removing=removing, checks=checks, original_check=original_check):
                    result = original_check(path, *args)
                    if path == manifest:
                        checks.append(True)
                        if len(checks) == (2 if removing else 1):
                            manifest.parent.rename(root / 'parked-state')
                            manifest.parent.symlink_to(outside, target_is_directory=True)
                    return result

                def written(path, *args, removing=removing, original_write=original_write, **kwargs):
                    if not removing and path.name == 'hooks.json':
                        raise OSError('configuration publication failed')
                    return original_write(path, *args, **kwargs)

                with patch.object(codex_hooks, 'require_unchanged', side_effect=checked), \
                        patch.object(codex_hooks, 'atomic_text', side_effect=written):
                    if removing:
                        uninstall(root)
                    else:
                        with self.assertRaises(OSError):
                            install(root)
                self.assertTrue(target.exists())
                self.assertEqual(target.read_text(), 'outside sentinel')
                self.assertFalse((root / 'parked-state' / manifest.name).exists())

    def test_preserves_user_hooks_across_install_and_uninstall(self):
        install(self.repo)
        once = self.path.read_text()
        install(self.repo)
        self.assertEqual(self.path.read_text(), once)
        data = json.loads(once)
        self.assertEqual(len(data['hooks']['SessionStart']), 2)
        uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)

    def test_preserves_user_additions_after_install(self):
        install(self.repo)
        data = json.loads(self.path.read_text())
        data['hooks']['Stop'].append({'hooks': [{'type': 'command', 'command': 'echo user'}]})
        self.path.write_text(json.dumps(data))
        uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text())['hooks']['Stop'],
                         [{'hooks': [{'type': 'command', 'command': 'echo user'}]}])

    def test_edited_owned_hook_is_not_overwritten(self):
        install(self.repo)
        data = json.loads(self.path.read_text())
        data['hooks']['Stop'][0]['hooks'][0]['timeout'] = 10
        self.path.write_text(json.dumps(data))
        before = self.path.read_text()
        with self.assertRaises(CommandError):
            uninstall(self.repo)
        self.assertEqual(self.path.read_text(), before)

    def test_invalid_json_preserved(self):
        self.path.write_text('broken')
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertEqual(self.path.read_text(), 'broken')

    def test_installed_handler_produces_valid_protocol_json(self):
        install(self.repo)
        data = json.loads(self.path.read_text())
        command = data['hooks']['SessionStart'][-1]['hooks'][0]['command']
        subprocess.run(['sh', '-n'], input=command, text=True, check=True, capture_output=True)
        argv = shlex.split(command)
        env = dict(os.environ)
        for assignment in argv[:2]:
            name, value = assignment.split('=', 1)
            self.assertIn(name, ('PYTHONDONTWRITEBYTECODE', 'PYTHONPATH'))
            env[name] = value
        result = subprocess.run(argv[2:], env=env, cwd=self.repo,
                                input=json.dumps({'hook_event_name': 'SessionStart'}),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['hookEventName'], 'SessionStart')

    def test_forged_manifest_cannot_authorize_removing_unrelated_hooks(self):
        install(self.repo)
        before = self.path.read_text()
        manifest = self.repo / '.ai-pilled' / 'codex-installation.json'
        manifest.write_text(json.dumps({'groups': self.original['hooks']}))
        with self.assertRaises(CommandError):
            uninstall(self.repo)
        self.assertEqual(self.path.read_text(), before)

    def test_invalid_installation_metadata_is_preserved(self):
        install(self.repo)
        before = self.path.read_text()
        manifest = self.repo / '.ai-pilled' / 'codex-installation.json'
        for data in ({}, {'groups': []}, {'groups': {}}, {'other': 'field'}):
            manifest.write_text(json.dumps(data))
            for operation in (install, uninstall):
                with self.assertRaises(CommandError):
                    operation(self.repo)
            self.assertEqual(self.path.read_text(), before)
            self.assertEqual(json.loads(manifest.read_text()), data)

    def test_dangling_hook_configuration_symlink_is_preserved(self):
        self.path.unlink()
        self.path.symlink_to(self.repo / 'missing')
        with self.assertRaises(CommandError):
            install(self.repo)
        self.assertTrue(self.path.is_symlink())

    def test_legacy_scoped_hooks_can_be_removed_without_touching_user_hooks(self):
        from ai_pilled.codex_hooks import groups
        legacy = groups(self.repo)
        legacy['PostToolUse'][0]['matcher'] = 'Bash|apply_patch|Write|Edit'
        legacy['PostToolUse'][0]['hooks'][0]['statusMessage'] = 'ai-pilled: credential scan'
        data = json.loads(json.dumps(self.original))
        for event, entries in legacy.items():
            data['hooks'].setdefault(event, []).extend(entries)
        self.path.write_text(json.dumps(data))
        state = self.repo / '.ai-pilled'
        state.mkdir()
        (state / 'codex-installation.json').write_text(json.dumps({'groups': legacy}))
        with self.assertRaises(CommandError):
            install(self.repo)
        uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)
        install(self.repo)
        data = json.loads(self.path.read_text())
        self.assertEqual(data['hooks']['PostToolUse'][0]['matcher'], '*')

    def test_named_pipe_configuration_is_rejected_without_waiting(self):
        import sys
        self.path.unlink()
        os.mkfifo(self.path)
        result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo),
                                 'install-codex-hooks'], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1], timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertIn('regular file', result.stdout)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())

    def test_oversized_configuration_is_preserved_without_installing(self):
        content = ' ' * 1_000_000 + '{}'
        self.path.write_text(content)
        with self.assertRaisesRegex(CommandError, 'size limit'):
            install(self.repo)
        self.assertEqual(self.path.read_text(), content)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())

    def test_nonregular_installation_lock_is_rejected(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        os.mkfifo(state / 'codex-install.lock')
        with self.assertRaisesRegex(CommandError, 'regular file'):
            install(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)

    def test_installation_that_would_exceed_limit_preserves_original_and_manifest(self):
        data = dict(self.original, description='a' * 999_000)
        content = json.dumps(data)
        self.path.write_text(content)
        with self.assertRaisesRegex(CommandError, 'size limit'):
            install(self.repo)
        self.assertEqual(self.path.read_text(), content)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())

    def test_install_preserves_concurrent_configuration_edit_and_allows_retry(self):
        from ai_pilled.state import atomic_text
        changed = dict(self.original, description='concurrent edit')

        def publish(path, text, *args, **kwargs):
            result = atomic_text(path, text, *args, **kwargs)
            if path.name == 'codex-installation.json':
                self.path.write_text(json.dumps(changed))
            return result

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaisesRegex(CommandError, 'concurrently'):
                install(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), changed)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())
        install(self.repo)
        uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), changed)

    def test_install_does_not_replace_concurrent_manifest(self):
        from ai_pilled.state import atomic_text

        def publish(path, text, *args, **kwargs):
            if path.name == 'codex-installation.json':
                path.write_text('concurrent metadata')
            return atomic_text(path, text, *args, **kwargs)

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaises(FileExistsError):
                install(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)
        self.assertEqual((self.repo / '.ai-pilled' / 'codex-installation.json').read_text(),
                         'concurrent metadata')

    def test_install_uncertain_completion_retains_recovery_manifest(self):
        from ai_pilled.state import atomic_text

        def publish(path, text, *args, **kwargs):
            result = atomic_text(path, text, *args, **kwargs)
            if path == self.path:
                raise OSError('completion lost')
            return result

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaises(OSError):
                install(self.repo)
        self.assertTrue((self.repo / '.ai-pilled' / 'codex-installation.json').exists())
        install(self.repo)
        uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)

    def test_uninstall_preserves_concurrent_configuration_edit(self):
        from ai_pilled.state import atomic_text
        install(self.repo)
        changed = json.loads(self.path.read_text())
        changed['description'] = 'concurrent edit'

        def publish(path, text, *args, **kwargs):
            if path == self.path:
                path.write_text(json.dumps(changed))
            return atomic_text(path, text, *args, **kwargs)

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaisesRegex(CommandError, 'concurrently'):
                uninstall(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), changed)
        self.assertTrue((self.repo / '.ai-pilled' / 'codex-installation.json').exists())

    def test_uninstall_does_not_delete_replaced_manifest(self):
        from ai_pilled.state import atomic_text
        install(self.repo)
        manifest = self.repo / '.ai-pilled' / 'codex-installation.json'

        def publish(path, text, *args, **kwargs):
            result = atomic_text(path, text, *args, **kwargs)
            if path == self.path:
                manifest.write_text('concurrent metadata')
            return result

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaises(CommandError):
                uninstall(self.repo)
        self.assertEqual(manifest.read_text(), 'concurrent metadata')
        self.assertEqual(json.loads(self.path.read_text()), self.original)

    def test_install_failed_configuration_write_removes_owned_manifest(self):
        from ai_pilled.state import atomic_text

        def publish(path, text, *args, **kwargs):
            if path == self.path:
                raise OSError('write failed')
            return atomic_text(path, text, *args, **kwargs)

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaises(OSError):
                install(self.repo)
        self.assertEqual(json.loads(self.path.read_text()), self.original)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())

    def test_install_preserves_concurrent_symlink_and_its_target(self):
        from ai_pilled.state import atomic_text
        target = self.repo / 'user.json'
        target.write_text(json.dumps(self.original))

        def publish(path, text, *args, **kwargs):
            result = atomic_text(path, text, *args, **kwargs)
            if path.name == 'codex-installation.json':
                self.path.unlink()
                self.path.symlink_to(target)
            return result

        with patch('ai_pilled.codex_hooks.atomic_text', side_effect=publish):
            with self.assertRaises(CommandError):
                install(self.repo)
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(json.loads(target.read_text()), self.original)
        self.assertFalse((self.repo / '.ai-pilled' / 'codex-installation.json').exists())
