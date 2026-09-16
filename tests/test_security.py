import os
from unittest.mock import patch
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
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
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

    def test_completed_command_preserves_exit_status_without_echoing_output(self):
        from ai_pilled.runtime import run_completed
        result = run_completed([sys.executable, '-c',
                                'print("private command output"); raise SystemExit(1)'],
                               self.repo, acceptable_codes=(0, 1))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'private command output\n')
        self.assertNotIn('private command output', repr(result))

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

    def test_stderr_output_limit(self):
        with self.assertRaises(CommandError):
            run([sys.executable, '-c', 'import sys; sys.stderr.write("x" * 1000)'],
                self.repo, limit=100)

    def test_limit_stops_writer_before_process_finishes(self):
        import time
        started = time.monotonic()
        with self.assertRaises(CommandError) as error:
            run([sys.executable, '-c',
                 'import sys,time; sys.stderr.write("x" * 10000); sys.stderr.flush(); time.sleep(5)'],
                self.repo, timeout=4, limit=100)
        self.assertIn('output exceeded', str(error.exception))
        self.assertLess(time.monotonic() - started, 2)

    def test_pattern_scan_checks_staged_code_not_fixed_worktree(self):
        self.write('parse.py', 'eval(data)\n')
        self.write('parse.py', 'value = 1\n', stage=False)
        self.assertEqual(scan(self.repo).status, 'pass')
        self.assertEqual(scan(self.repo, patterns=True).status, 'fail')
        self.assertEqual(scan(self.repo, 'worktree', patterns=True).status, 'pass')

    def test_unicode_encoded_credentials_are_found_in_index_and_history(self):
        from ai_pilled.pre_push import scan_revision
        token = 'ghp_' + 'Z' * 36
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        for encoding in ('utf-16', 'utf-32'):
            (self.repo / 'encoded.txt').write_bytes(('first line\n' + token).encode(encoding))
            self.git('add', 'encoded.txt')
            self.assertEqual(scan(self.repo).findings[0].line, 2)
            self.assertEqual(scan(self.repo, 'worktree').status, 'fail')
            self.git('commit', '-qm', 'test: encoded credential fixture')
            self.assertEqual(scan_revision(self.repo, 'HEAD').status, 'fail')

    def test_slack_webhook_is_detected_without_echoing_it(self):
        webhook = 'https://hooks.slack.com/services/' + 'T' * 9 + '/' + 'B' * 9 + '/' + 'X' * 24
        self.write('settings.txt', webhook)
        result = scan(self.repo)
        self.assertEqual(result.findings[0].rule, 'slack-webhook')
        self.assertNotIn(webhook, json.dumps(result.to_dict()))

    def test_credential_in_file_name_is_blocked_without_echoing_it(self):
        token = 'ghp_' + 'Z' * 36
        self.write(token + '.txt', 'ordinary content')
        for scope in ('staged', 'worktree'):
            result = scan(self.repo, scope)
            self.assertEqual(result.status, 'fail')
            self.assertFalse(token in json.dumps(result.to_dict()))
            self.assertIn('file name', result.findings[0].message)


    def test_tracked_file_replaced_by_pipe_does_not_block_scan(self):
        self.write('pipe.txt', 'ordinary')
        (self.repo / 'pipe.txt').unlink()
        os.mkfifo(self.repo / 'pipe.txt')
        # A separate bounded process makes a blocking-read regression fail promptly.
        code = ('import json,sys; from ai_pilled.security import scan; '
                'print(json.dumps(scan(sys.argv[1], "worktree").to_dict()))')
        output = run([sys.executable, '-c', code, str(self.repo)],
                     Path(__file__).resolve().parents[1], timeout=5)
        result = json.loads(output)
        self.assertEqual(result['status'], 'incomplete')
        self.assertTrue(any('regular files' in f['message'] for f in result['findings']))


    def test_batched_binary_blobs_preserve_findings_and_path_order(self):
        token = ('ghp_' + 'Z' * 36).encode()
        content = b'\x00\nnot-a-header blob 99\n' + token + b'\n'
        self.write('empty.txt', '')
        for name in ('a.bin', 'b.bin', 'c.bin'):
            (self.repo / name).write_bytes(content)
            self.git('add', '--', name)
        with patch('ai_pilled.git_blobs.MAX_BATCH_BYTES', 160):
            result = scan(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual([f.path for f in result.findings], ['a.bin', 'b.bin', 'c.bin'])
        self.assertTrue(all(f.line == 3 for f in result.findings))

    def test_oversized_blob_does_not_hide_neighboring_credentials(self):
        self.write('a.txt', 'ordinary')
        self.write('large.txt', 'x' * 2_000_001)
        self.write('z.txt', 'ghp_' + 'Z' * 36)
        result = scan(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual([f.rule for f in result.findings], ['scan-incomplete', 'github-token'])

    def test_missing_blob_does_not_hide_other_findings(self):
        self.write('missing.txt', 'missing blob fixture')
        oid = self.git('rev-parse', ':missing.txt').decode().strip()
        (self.repo / '.git' / 'objects' / oid[:2] / oid[2:]).unlink()
        self.write('secret.txt', 'ghp_' + 'Z' * 36)
        result = scan(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertEqual([f.rule for f in result.findings], ['scan-incomplete', 'github-token'])

    def test_malformed_batch_output_is_incomplete(self):
        self.write('ordinary.txt', 'ordinary')
        def corrupt(argv, *args, **kwargs):
            if argv == ['git', 'cat-file', '--batch']:
                return b'invalid header\n'
            return run(argv, *args, **kwargs)
        with patch('ai_pilled.git_blobs.run', side_effect=corrupt):
            result = scan(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'scan-incomplete')


    def test_aws_secret_key_assignments_are_detected_without_access_key_id(self):
        secret = 'aB3/+' * 8
        for prefix, suffix in (('AWS_SECRET_ACCESS_KEY=', ''),
                               ('aws_secret_access_key = "', '"'),
                               ('"SecretAccessKey": "', '"'),
                               ("secretAccessKey: '", "'")):
            with self.subTest(prefix=prefix):
                self.write('credentials.txt', prefix + secret + suffix)
                result = scan(self.repo)
                self.assertEqual(result.status, 'fail')
                self.assertEqual(result.findings[0].rule, 'aws-secret-key')
                self.assertNotIn(secret, json.dumps(result.to_dict()))

    def test_aws_environment_references_and_unrelated_values_are_not_secrets(self):
        self.write('settings.txt', 'AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}\n'
                   'secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY\n'
                   'unrelated_value=' + 'aB3/+' * 8)
        self.assertEqual(scan(self.repo).status, 'pass')

    def test_replaced_blob_cannot_hide_staged_credentials(self):
        token = 'ghp_' + 'R' * 36
        self.write('credential.txt', token)
        unsafe = self.git('rev-parse', ':credential.txt').decode().strip()
        self.write('clean.txt', 'ordinary content')
        clean = self.git('rev-parse', ':clean.txt').decode().strip()
        self.git('replace', unsafe, clean)
        result = scan(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == 'credential.txt' for f in result.findings))
        self.assertNotIn(token, json.dumps(result.to_dict()))
