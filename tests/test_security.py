import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ai_pilled.runtime import CommandError, run
from ai_pilled.security import scan


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ai-pilled test ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True,
                              capture_output=True).stdout

    def write(self, name, content, stage=True):
        (self.repo / name).write_text(content)
        if stage:
            self.git('add', '--', name)

    def test_index_content_not_worktree_is_checked(self):
        token = 'AKIA' + 'Q' * 16
        self.write('credentials.txt', token)
        self.write('credentials.txt', 'removed in working tree', stage=False)
        result = scan(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].path, 'credentials.txt')
        self.assertNotIn(token, json.dumps(result.to_dict()))
        self.assertEqual(scan(self.repo, 'worktree').status, 'pass')

    def test_untracked_files_are_scanned_only_in_worktree_mode(self):
        self.write('new file.txt', 'ghp_' + 'A' * 36, stage=False)
        self.assertEqual(scan(self.repo).status, 'pass')
        self.assertEqual(scan(self.repo, 'worktree').status, 'fail')

    def test_clean_snapshot_changes_with_content(self):
        self.write('file.txt', 'first')
        before = scan(self.repo)
        self.write('file.txt', 'second')
        after = scan(self.repo)
        self.assertEqual(after.status, 'pass')
        self.assertNotEqual(before.snapshot, after.snapshot)

    def test_large_file_is_incomplete_not_pass(self):
        self.write('large.txt', 'x' * 2_000_001)
        self.assertEqual(scan(self.repo).status, 'incomplete')

    def test_path_with_newlines_preserved(self):
        name = 'odd\nfile.txt'
        self.write(name, 'sk-' + 'A' * 40)
        self.assertEqual(scan(self.repo).findings[0].path, name)

    def test_symlink_does_not_read_external_file(self):
        outside = self.repo.parent / (self.repo.name + '-secret')
        outside.write_text('ghp_' + 'B' * 36)
        self.addCleanup(outside.unlink)
        (self.repo / 'link').symlink_to(outside)
        result = scan(self.repo, 'worktree')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'scan-incomplete')

    def test_ignored_file_is_excluded(self):
        self.write('.gitignore', 'ignored.txt\n')
        self.write('ignored.txt', 'ghp_' + 'A' * 36, stage=False)
        self.assertEqual(scan(self.repo, 'worktree').status, 'pass')

    def test_subprocess_timeout_is_error(self):
        with self.assertRaises(CommandError):
            run([sys.executable, '-c', 'import time; time.sleep(5)'], self.repo, timeout=.05)

    def test_subprocess_failure_does_not_leak_stderr(self):
        with self.assertRaises(CommandError) as error:
            run([sys.executable, '-c', 'import sys; sys.stderr.write("secret"); sys.exit(1)'], self.repo)
        self.assertNotIn('secret', str(error.exception))

    def test_subprocess_output_limit(self):
        with self.assertRaises(CommandError):
            run([sys.executable, '-c', 'print("x" * 100)'], self.repo, limit=10)


if __name__ == '__main__':
    unittest.main()
