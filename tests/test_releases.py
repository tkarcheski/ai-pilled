import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.releases import release_plan


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.commit('chore: initial')
        self.git('tag', 'v1.2.3')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def commit(self, message):
        self.git('commit', '--allow-empty', '-qm', message)

    def test_semantic_bump_priority_and_explicit_base(self):
        self.commit('fix: repair parser')
        result = release_plan(self.repo, '1.2.3', 'v1.2.3')
        self.assertEqual((result.status, result.bump, result.next_version), ('pass', 'patch', '1.2.4'))
        self.commit('feat: add workflow')
        self.assertEqual(release_plan(self.repo, '1.2.3', 'v1.2.3').next_version, '1.3.0')
        self.commit('refactor!: remove old protocol')
        self.assertEqual(release_plan(self.repo, '1.2.3', 'v1.2.3').next_version, '2.0.0')
        self.assertNotIn('chore: initial', result.changelog)

    def test_breaking_footer_is_detected(self):
        self.commit('feat: change response\n\nBREAKING CHANGE: response is now structured')
        self.assertEqual(release_plan(self.repo, '0.3.0', 'v1.2.3').next_version, '1.0.0')

    def test_documentation_and_empty_range_do_not_invent_release(self):
        result = release_plan(self.repo, '1.2.3', 'HEAD')
        self.assertEqual(result.bump, 'none')
        self.assertIn('No commits', result.changelog)
        self.commit('docs: clarify setup')
        result = release_plan(self.repo, '1.2.3', 'v1.2.3')
        self.assertEqual(result.next_version, '1.2.3')
        self.assertEqual(result.bump, 'none')

    def test_invalid_or_non_ancestor_base_is_incomplete(self):
        self.assertEqual(release_plan(self.repo, '01.2.3').status, 'incomplete')
        self.assertEqual(release_plan(self.repo, '1.2.3', '--all').status, 'incomplete')
        self.git('checkout', '--orphan', 'unrelated')
        self.commit('feat: unrelated root')
        self.assertEqual(release_plan(self.repo, '1.2.3', 'v1.2.3').status, 'incomplete')

    def test_markdown_is_escaped_and_credentials_never_become_notes(self):
        self.commit('fix: <script>alert(1)</script> [link](https://example.test)')
        result = release_plan(self.repo, '1.2.3', 'v1.2.3')
        self.assertNotIn('<script>', result.changelog)
        self.assertIn('&lt;script&gt;', result.changelog)
        self.assertNotIn('[link]', result.changelog)
        token = 'ghp_' + 'A' * 36
        self.commit('fix: secret\n\n' + token)
        result = release_plan(self.repo, '1.2.3', 'v1.2.3')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.changelog, '')
        self.assertNotIn(token, str(result.to_dict()))

    def prepare_fixture(self, test_code=0):
        import json
        import sys
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'commands': {'test': [sys.executable, '-c', f'raise SystemExit({test_code})']}}))
        (self.repo / 'VERSION').write_text('1.2.3\n')
        (self.repo / 'CHANGELOG.md').write_text('# Changelog\n\n## 1.2.3\n\nHandwritten history.\n')
        self.git('add', '.gitignore', '.ai-pilled.json', 'VERSION', 'CHANGELOG.md')
        self.git('commit', '-qm', 'feat: releasable change')

    def test_release_preparation_requires_checks_and_preserves_history(self):
        from ai_pilled.releases import prepare_release
        self.prepare_fixture()
        before_head = self.git('rev-parse', 'HEAD')
        result = prepare_release(self.repo, '1.2.3', 'v1.2.3')
        self.assertEqual(result.status, 'pass')
        self.assertEqual((self.repo / 'VERSION').read_text(), '1.3.0\n')
        notes = (self.repo / 'CHANGELOG.md').read_text()
        self.assertIn('## 1.3.0', notes)
        self.assertIn('Handwritten history.', notes)
        self.assertEqual(self.git('rev-parse', 'HEAD'), before_head)
        self.assertEqual(self.git('diff', '--cached'), b'')

    def test_failed_readiness_does_not_write_release_metadata(self):
        from ai_pilled.releases import prepare_release
        self.prepare_fixture(test_code=1)
        before = (self.repo / 'CHANGELOG.md').read_bytes()
        self.assertEqual(prepare_release(self.repo, '1.2.3', 'v1.2.3').status, 'fail')
        self.assertEqual((self.repo / 'VERSION').read_text(), '1.2.3\n')
        self.assertEqual((self.repo / 'CHANGELOG.md').read_bytes(), before)

    def test_release_version_mismatch_and_dirty_tree_are_rejected(self):
        from ai_pilled.releases import prepare_release
        self.prepare_fixture()
        self.assertEqual(prepare_release(self.repo, '2.0.0', 'v1.2.3').status, 'incomplete')
        (self.repo / 'uncommitted').write_text('change')
        self.assertEqual(prepare_release(self.repo, '1.2.3', 'v1.2.3').status, 'fail')
        self.assertEqual((self.repo / 'VERSION').read_text(), '1.2.3\n')

    def test_second_write_failure_restores_first_file(self):
        from ai_pilled.releases import prepare_release
        from ai_pilled.state import atomic_text
        self.prepare_fixture()
        calls = []
        def write(path, text, mode):
            calls.append(path.name)
            if len(calls) == 2:
                raise OSError('simulated write failure')
            return atomic_text(path, text, mode)
        with patch('ai_pilled.state.atomic_text', side_effect=write):
            result = prepare_release(self.repo, '1.2.3', 'v1.2.3')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual((self.repo / 'VERSION').read_text(), '1.2.3\n')
        self.assertEqual(self.git('status', '--porcelain'), b'')
