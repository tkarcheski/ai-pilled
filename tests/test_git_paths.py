"""Git path records must never redirect validation to a whitespace-trimmed sibling."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.git_hooks import install, uninstall
from ai_pilled.pipeline import quality
from ai_pilled.runtime import CommandError, git_path
from ai_pilled.security import scan
from ai_pilled.staged_review import review_checks


class GitPathTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                                if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.clean = self.create_repo('repo', 'ordinary')

    def git(self, repo, *args):
        return subprocess.run(['git', *args], cwd=repo, capture_output=True, check=True).stdout

    def create_repo(self, name, content):
        repo = self.base / name
        repo.mkdir()
        self.git(repo, 'init', '-q')
        self.git(repo, 'config', 'user.name', 'Path fixture')
        self.git(repo, 'config', 'user.email', 'path@example.invalid')
        (repo / '.gitignore').write_text('.ai-pilled/\n')
        (repo / 'value.txt').write_text(content)
        self.git(repo, 'add', '.gitignore', 'value.txt')
        return repo

    def test_whitespace_and_non_utf8_roots_scan_the_selected_repository(self):
        for suffix in (' ', '\n', '\t', '\r', os.fsdecode(b'\xff')):
            with self.subTest(suffix=suffix):
                repo = self.create_repo('repo' + suffix, 'ghp_' + 'A' * 36)
                for scope in ('staged', 'worktree'):
                    result = scan(repo, scope)
                    self.assertEqual(result.status, 'fail')
                    self.assertEqual(result.findings[0].rule, 'github-token')
        self.assertEqual(scan(self.clean).status, 'pass')

    def test_comprehensive_review_and_quality_do_not_borrow_sibling_evidence(self):
        repo = self.create_repo('repo\n', 'ghp_' + 'A' * 36)
        for check in (quality, review_checks):
            result = check(repo)
            self.assertEqual(result.status, 'fail')
            self.assertTrue(any(f.rule.endswith('github-token') for f in result.findings))
        self.assertFalse((self.clean / '.ai-pilled').exists())

    def test_hook_installation_targets_exact_root_and_blocks_real_commit(self):
        repo = self.create_repo('repo\n', 'ghp_' + 'A' * 36)
        install(repo)
        self.assertTrue((repo / '.ai-pilled/hooks/pre-commit').is_file())
        self.assertFalse((self.clean / '.ai-pilled').exists())
        result = subprocess.run(['git', 'commit', '-m', 'feat: rejected credential'],
                                cwd=repo, capture_output=True, timeout=10, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'github-token', result.stdout + result.stderr)
        uninstall(repo)
        self.assertFalse((repo / '.ai-pilled/hooks').exists())

    def test_git_path_decoder_preserves_bytes_and_rejects_invalid_records(self):
        self.assertEqual(git_path(b'/selected path \n\n'), Path('/selected path \n'))
        self.assertEqual(os.fsencode(git_path(b'/selected-\xff\n')), b'/selected-\xff')
        for value in (b'', b'\n', b'/unterminated', b'/null\0path\n'):
            with self.assertRaises(CommandError):
                git_path(value)
