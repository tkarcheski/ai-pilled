import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.publishing import publish_release
from ai_pilled.runtime import run as real_run


class PublishingTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / 'VERSION').write_text('1.2.3\n')
        (self.repo / 'CHANGELOG.md').write_text('# Changelog\n\n## 1.2.3\n\nNew behavior.\n\n## 1.2.2\n\nOlder notes.\n')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'aggressiveness': 'lazy',
            'commands': {'test': [sys.executable, '-c', 'pass']}}))
        self.commit()
        self.git('tag', 'v1.2.3')
        self.remote_head = self.head
        self.response = {'tagName': 'v1.2.3', 'isDraft': False, 'isPrerelease': False,
                         'body': 'New behavior.', 'publishedAt': '2026-09-16T00:00:00Z'}
        self.calls = []
        fake = patch('ai_pilled.publishing.run', side_effect=self.run_command)
        fake.start()
        self.addCleanup(fake.stop)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def commit(self):
        self.git('add', 'VERSION', 'CHANGELOG.md', '.gitignore', '.ai-pilled.json')
        self.git('commit', '-qm', 'chore: prepare release')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()

    def run_command(self, argv, cwd, **kwargs):
        if argv[0] != 'fake-gh':
            return real_run(argv, cwd, **kwargs)
        self.calls.append(argv)
        if argv[1] == 'api':
            return self.remote_head.encode()
        if argv[2] == 'create':
            self.assertIn('--verify-tag', argv)
            self.assertEqual(argv[argv.index('--target') + 1], self.head)
            self.assertEqual(argv[argv.index('--notes-file') + 1], '-')
            self.assertEqual(kwargs['input_data'], b'New behavior.')
            return b''
        self.assertEqual(argv[2], 'view')
        return json.dumps(self.response).encode()

    def invoke(self, publish=False):
        return publish_release(self.repo, 'owner/repo', 'v1.2.3', self.head, publish, 'fake-gh')

    def test_preview_validates_tags_and_limits_notes_to_selected_version(self):
        result = self.invoke()
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.action, 'preview')
        self.assertEqual(result.notes, 'New behavior.')
        self.assertTrue(all(call[1] == 'api' for call in self.calls))
        self.assertEqual(self.git('status', '--porcelain'), b'')

    def test_explicit_publish_uses_stdin_and_confirms_server_result(self):
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.action, 'published')
        self.assertEqual(sum(call[1:3] == ['release', 'create'] for call in self.calls), 1)

    def test_remote_tag_mismatch_never_creates_release(self):
        self.remote_head = 'b' * 40
        self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertTrue(all(call[1] == 'api' for call in self.calls))

    def test_dirty_or_stale_local_snapshot_never_contacts_github(self):
        (self.repo / 'VERSION').write_text('2.0.0\n')
        self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertEqual(publish_release(self.repo, 'owner/repo', 'v1.2.3', 'a' * 40).status, 'incomplete')
        self.assertEqual(self.calls, [])

    def test_version_and_duplicate_notes_mismatch_are_blocked(self):
        (self.repo / 'VERSION').write_text('9.9.9\n')
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        (self.repo / 'VERSION').write_text('1.2.3\n')
        (self.repo / 'CHANGELOG.md').write_text('## 1.2.3\nOne.\n## 1.2.3\nTwo.\n')
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertEqual(self.calls, [])

    def test_credentials_in_notes_are_neither_previewed_nor_sent(self):
        token = 'ghp_' + 'Z' * 36
        (self.repo / 'CHANGELOG.md').write_text('## 1.2.3\n' + token + '\n')
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn(token, str(result.to_dict()))
        self.assertEqual(self.calls, [])

    def test_bad_remote_confirmation_is_not_success(self):
        self.response['isDraft'] = True
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'unconfirmed')

    def test_failed_quality_blocks_publication(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {
            'test': [sys.executable, '-c', 'raise SystemExit(1)']}}))
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(self.calls, [])
