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
