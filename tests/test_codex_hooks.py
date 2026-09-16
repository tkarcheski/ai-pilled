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
