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
        self.tag_object = None
        self.tag_ref = 'refs/tags/v1.2.3'
        self.annotations = {}
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
            endpoint = argv[4]
            if endpoint == 'repos/owner/repo/git/ref/tags/v1.2.3':
                return json.dumps({'ref': self.tag_ref, 'object': self.tag_object or {
                    'type': 'commit', 'sha': self.remote_head}}).encode()
            prefix = 'repos/owner/repo/git/tags/'
            self.assertTrue(endpoint.startswith(prefix), endpoint)
            return json.dumps(self.annotations[endpoint.removeprefix(prefix)]).encode()
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

    def test_hidden_metadata_cannot_substitute_for_committed_release_version(self):
        (self.repo / 'VERSION').write_text('9.9.9\n')
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        self.remote_head = self.head
        self.git('update-index', '--assume-unchanged', 'VERSION')
        (self.repo / 'VERSION').write_text('1.2.3\n')
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'not-published')
        self.assertEqual(self.calls, [])
        self.assertEqual((self.repo / 'VERSION').read_text(), '1.2.3\n')

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

    def test_metadata_replaced_before_open_blocks_provider(self):
        from ai_pilled.file_io import read_regular
        version = self.repo / 'VERSION'
        def replaced(path, maximum):
            if path == version:
                path.unlink()
                os.mkfifo(path)
            return read_regular(path, maximum)
        with patch('ai_pilled.publishing.read_regular', side_effect=replaced):
            result = self.invoke(publish=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'not-published')
        self.assertEqual(self.calls, [])
        self.assertTrue(version.is_fifo())

    def test_failed_quality_blocks_publication(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {
            'test': [sys.executable, '-c', 'raise SystemExit(1)']}}))
        self.commit()
        self.git('tag', '-f', 'v1.2.3')
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(self.calls, [])

    def test_annotated_tags_are_peeled_to_the_verified_commit(self):
        first, second = 'a' * 40, 'b' * 40
        self.tag_object = {'type': 'tag', 'sha': first}
        self.annotations = {
            first: {'sha': first, 'object': {'type': 'tag', 'sha': second}},
            second: {'sha': second, 'object': {'type': 'commit', 'sha': self.head}},
        }
        result = self.invoke(publish=True)
        self.assertEqual(result.action, 'published', result.to_dict())
        self.assertEqual(sum(call[1] == 'api' for call in self.calls), 9)

    def test_same_named_branch_cannot_supply_tag_evidence(self):
        self.tag_ref = 'refs/heads/v1.2.3'
        result = self.invoke(publish=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.action, 'not-published')
        self.assertTrue(all(call[1] == 'api' for call in self.calls))

    def test_malformed_or_noncommit_tag_objects_block_publication(self):
        for target in ({'type': 'tree', 'sha': self.head}, {'type': 'commit', 'sha': True},
                       {'type': 'commit', 'sha': '../outside'}, ['invalid']):
            with self.subTest(target=target):
                self.tag_object = target
                self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertTrue(all(call[1] == 'api' for call in self.calls))

    def test_annotated_tag_identity_cycles_and_target_mismatch_are_blocked(self):
        sha = 'a' * 40
        self.tag_object = {'type': 'tag', 'sha': sha}
        for annotation in (
                {'sha': 'b' * 40, 'object': {'type': 'commit', 'sha': self.head}},
                {'sha': sha, 'object': self.tag_object},
                {'sha': sha, 'object': {'type': 'commit', 'sha': 'b' * 40}},
                {'sha': sha, 'object': None}, []):
            with self.subTest(annotation=annotation):
                self.annotations = {sha: annotation}
                self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertTrue(all(call[1] == 'api' for call in self.calls))

    def test_annotation_chain_is_bounded(self):
        hashes = [format(i, '040x') for i in range(17)]
        self.tag_object = {'type': 'tag', 'sha': hashes[0]}
        self.annotations = {sha: {'sha': sha, 'object': {'type': 'tag', 'sha': hashes[i + 1]}}
                            for i, sha in enumerate(hashes[:-1])}
        self.assertEqual(self.invoke(publish=True).status, 'incomplete')
        self.assertEqual(len(self.calls), 17)
        self.assertTrue(all(call[1] == 'api' for call in self.calls))
        self.calls.clear()
        self.annotations[hashes[15]]['object'] = {'type': 'commit', 'sha': self.head}
        self.assertEqual(self.invoke().status, 'pass')
        self.assertEqual(len(self.calls), 17)

    def test_tag_movement_before_create_blocks_and_after_create_is_unconfirmed(self):
        original = self.run_command
        for change_at, expected in ((2, 'preview'), (3, 'unconfirmed')):
            with self.subTest(change_at=change_at):
                self.calls.clear()
                self.remote_head = self.head
                reads = 0
                def changed(argv, cwd, change_at=change_at, **kwargs):
                    nonlocal reads
                    if argv[0] == 'fake-gh' and argv[1] == 'api':
                        reads += 1
                        if reads == change_at:
                            self.remote_head = 'b' * 40
                    return original(argv, cwd, **kwargs)
                with patch('ai_pilled.publishing.run', side_effect=changed):
                    result = self.invoke(publish=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, expected)
                self.assertEqual(sum(call[1:3] == ['release', 'create'] for call in self.calls),
                                 int(change_at == 3))

    def test_invalid_publication_timestamps_are_unconfirmed(self):
        for at in (True, {'invalid': 'timestamp'}, '', '2026-09-16', '2026-09-16T00:00:00',
                   '2026-02-30T00:00:00Z', '2026-09-16T00:00:00+25:00', '0001-01-01T00:00:00Z'):
            with self.subTest(at=at):
                self.response['publishedAt'] = at
                result = self.invoke(publish=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.action, 'unconfirmed')

    def test_publication_timestamp_accepts_offsets_and_fractional_seconds(self):
        for at in ('2026-09-16T00:00:00+00:00', '2026-09-15T19:00:00-05:00',
                   '2026-09-16T00:00:00.123456789Z'):
            with self.subTest(at=at):
                self.response['publishedAt'] = at
                self.assertEqual(self.invoke(publish=True).action, 'published')
