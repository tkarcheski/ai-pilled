import os
from unittest.mock import patch
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ai_pilled.runtime import CommandError, Report, run
from ai_pilled.security import scan, scan_text


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

    def test_pypi_publishing_tokens_are_detected_in_contents_and_filenames(self):
        token = 'pypi-' + 'Ab0_-' * 17
        self.write('publishing.txt', token)
        self.write(token + '.txt', 'ordinary')
        for scope in ('staged', 'worktree'):
            result = scan(self.repo, scope)
            self.assertEqual(result.status, 'fail')
            self.assertEqual({finding.rule for finding in result.findings}, {'pypi-token'})
            self.assertEqual(len(result.findings), 2)
            self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_short_pypi_examples_are_not_treated_as_tokens(self):
        self.write('notes.txt', 'pypi-example\npypi-' + 'A' * 84)
        self.assertEqual(scan(self.repo).status, 'pass')


    def test_json_escaped_credentials_are_detected_without_losing_duplicate_keys(self):
        token = 'ghp_' + 'A' * 36
        escaped = json.dumps(token).replace('g', r'\u0067', 1)
        self.write('encoded.json', '{\n "value": ' + escaped + ', "value": "ordinary"\n}')
        result = scan(self.repo)
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('github-token', 2)])
        self.assertNotIn(token, json.dumps(result.to_dict()))
        self.assertNotIn(escaped, json.dumps(result.to_dict()))

    def test_json_literal_scanning_does_not_duplicate_raw_findings(self):
        self.write('plain.json', json.dumps('ghp_' + 'A' * 36))
        self.assertEqual(len(scan(self.repo).findings), 1)

    def test_unterminated_escaped_quotes_do_not_hide_the_next_line(self):
        encoded = json.dumps('pypi-' + 'A' * 85).replace('p', r'\u0070', 1)
        text = '"' + r'\"' * 20000 + '\n' + encoded
        report = Report('security')
        scan_text(report, 'fixture', text)
        self.assertEqual([(f.rule, f.line) for f in report.findings], [('pypi-token', 2)])

    def test_non_ascii_neighbors_cannot_hide_ascii_credentials(self):
        tokens = [('AKIA' + 'A' * 16, 'aws-access-key'),
                  ('ghp_' + 'A' * 36, 'github-token'),
                  ('github_pat_' + 'A' * 40, 'github-fine-grained-token'),
                  ('pypi-' + 'A' * 85, 'pypi-token'),
                  ('sk-' + 'A' * 32, 'openai-token'),
                  ('xoxb-' + 'A' * 20, 'slack-token'),
                  ('aws_secret_access_key=' + 'A' * 40, 'aws-secret-key')]
        for token, rule in tokens:
            with self.subTest(rule=rule):
                (self.repo / 'binary.bin').write_bytes(bytes([255]) + token.encode() + bytes([255]))
                self.git('add', 'binary.bin')
                for scope in ('staged', 'worktree'):
                    result = scan(self.repo, scope)
                    self.assertEqual(result.status, 'fail')
                    self.assertEqual(result.findings[0].rule, rule)

    def test_ascii_identifier_prefixes_keep_existing_token_boundaries(self):
        self.write('ordinary.txt', 'prefixghp_' + 'A' * 36)
        self.assertEqual(scan(self.repo).status, 'pass')

    def test_json_aws_secret_fields_are_decoded_with_their_values(self):
        secret = 'aB3/+' * 8
        for key in ('aws_secret_access_key', 'AWS_SECRET_ACCESS_KEY', 'SecretAccessKey'):
            with self.subTest(key=key):
                encoded_key = json.dumps(key).replace(key[0], r'\u%04x' % ord(key[0]), 1)
                encoded_value = json.dumps(secret).replace('a', r'\u0061', 1)
                source = '{\n' + encoded_key + ':\n' + encoded_value + ', ' + encoded_key + ': "ordinary"}'
                self.write('encoded.json', source)
                result = scan(self.repo)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('aws-secret-key', 3)])

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
        code = ('import json,sys; from ai_pilled.security import scan, scan_text; '
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

    def test_python_adjacent_and_escaped_literals_are_credentials_without_pattern_opt_in(self):
        token = 'ghp_' + 'A' * 36
        forms = ["'ghp_' '" + 'A' * 36 + "'",
                 "b'ghp_' b'" + 'A' * 36 + "'",
                 "'" + ''.join('\\x%02x' % ord(char) for char in token) + "'",
                 "('ghp_'\n '" + 'A' * 36 + "')"]
        for literal in forms:
            with self.subTest(literal=literal):
                self.write('literal.py', 'value = ' + literal + '\n')
                for scope in ('staged', 'worktree'):
                    result = scan(self.repo, scope)
                    self.assertEqual([(f.rule, f.line) for f in result.findings], [('github-token', 1)])
                    self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_python_literal_scanning_never_executes_code(self):
        self.write('literal.py', 'raise RuntimeError("must not run")\nvalue = "ordinary"\n')
        self.assertEqual(scan(self.repo).status, 'pass')
        self.write('literal.py', 'value = "ghp_" + "A" * 36\n')
        self.assertEqual(scan(self.repo).status, 'pass')
        self.write('literal.py', 'def broken(')
        self.assertEqual(scan(self.repo).status, 'incomplete')

    def test_raw_python_literal_findings_are_not_duplicated(self):
        self.write('literal.py', 'value = ' + repr('ghp_' + 'A' * 36))
        self.assertEqual(len(scan(self.repo).findings), 1)

    def test_history_cache_separates_python_literals_from_identical_text_blobs(self):
        from ai_pilled.pre_push import scan_revision
        source = "value = 'ghp_' '" + 'A' * 36 + "'\n"
        self.write('a.txt', source)
        self.write('z.py', source)
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('commit', '-qm', 'test: literal fixture')
        cache = {}
        result = scan_revision(self.repo, 'HEAD', cache=cache)
        self.assertEqual([(f.rule, f.path) for f in result.findings], [('github-token', 'z.py')])
        self.assertEqual(scan_revision(self.repo, 'HEAD', cache=cache).to_dict(), result.to_dict())
        self.assertNotIn('A' * 36, repr(cache))

    def test_gitlab_and_stripe_server_keys_cover_contents_and_names(self):
        tokens = [('glpat-' + 'Ab0_-' * 4, 'gitlab-access-token')]
        tokens.extend((prefix + 'Ab01' * 6, 'stripe-secret-key')
                      for prefix in ('sk_live_', 'sk_test_', 'rk_live_', 'rk_test_', 'sk_org_'))
        for index, (token, _) in enumerate(tokens):
            self.write(str(index) + '.txt', token)
            self.write(token + '.txt', 'ordinary')
        for scope in ('staged', 'worktree'):
            result = scan(self.repo, scope)
            self.assertEqual(result.status, 'fail')
            self.assertEqual(len(result.findings), 2 * len(tokens))
            self.assertEqual({f.rule for f in result.findings}, {'gitlab-access-token', 'stripe-secret-key'})
            for token, _ in tokens:
                self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_gitlab_and_stripe_encoded_literals_keep_credential_checks(self):
        from ai_pilled.security import scan_bytes
        for prefix, length, rule in (('glpat-', 20, 'gitlab-access-token'),
                                     ('rk_live_', 24, 'stripe-secret-key'),
                                     ('sk_org_', 24, 'stripe-secret-key')):
            token = prefix + 'A' * length
            cases = [('encoded.json', json.dumps(token).replace(prefix[0], r'\u%04x' % ord(prefix[0]), 1).encode()),
                     ('encoded.py', ('value = ' + repr(prefix) + ' ' + repr('A' * length)).encode()),
                     ('binary.bin', bytes([255]) + token.encode() + bytes([255]))]
            for path, content in cases:
                with self.subTest(prefix=prefix, path=path):
                    result = Report('security')
                    scan_bytes(result, path, content)
                    self.assertEqual([f.rule for f in result.findings], [rule])
                    self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_public_stripe_keys_and_short_prefix_examples_remain_allowed(self):
        values = ['pk_live_' + 'A' * 100, 'pk_test_' + 'A' * 100,
                  'glpat-' + 'A' * 19, 'sk_live_' + 'A' * 23,
                  'rk_test_example', 'sk_org_example', 'prefixglpat-' + 'A' * 20]
        self.write('ordinary.txt', '\n'.join(values))
        self.assertEqual(scan(self.repo).status, 'pass')

    def test_worktree_changes_after_read_cannot_certify_stale_content(self):
        from contextlib import contextmanager
        path = self.repo / 'config.txt'
        token = 'ghp_' + 'Z' * 36
        original = os.fdopen
        for change in ('replace', 'edit', 'delete', 'mode', 'symlink'):
            with self.subTest(change=change):
                if path.is_symlink():
                    path.unlink()
                self.write(path.name, 'ordinary')
                @contextmanager
                def changed(fd, *args, change=change, **kwargs):
                    with original(fd, *args, **kwargs) as stream:
                        yield stream
                    if change == 'replace':
                        replacement = self.repo / 'replacement'
                        replacement.write_text(token)
                        replacement.replace(path)
                    elif change == 'edit':
                        path.write_text(token)
                    elif change == 'delete':
                        path.unlink()
                    elif change == 'mode':
                        path.chmod(0o700)
                    else:
                        path.unlink()
                        path.symlink_to('/dev/null')
                with patch('ai_pilled.security.os.fdopen', side_effect=changed):
                    result = scan(self.repo, 'worktree')
                self.assertEqual(result.status, 'incomplete', result.to_dict())
                self.assertEqual(result.findings[0].rule, 'scan-incomplete')
                self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_worktree_mutation_during_descriptor_read_is_incomplete(self):
        from contextlib import contextmanager
        path = self.repo / 'config.txt'
        self.write(path.name, 'ordinary')
        original = os.fdopen
        class MutatingReader:
            def __init__(self, stream):
                self.stream = stream
            def fileno(self):
                return self.stream.fileno()
            def read(self, size):
                data = self.stream.read(size)
                path.write_text('changed!')
                return data
        @contextmanager
        def changed(fd, *args, **kwargs):
            with original(fd, *args, **kwargs) as stream:
                yield MutatingReader(stream)
        with patch('ai_pilled.security.os.fdopen', side_effect=changed):
            result = scan(self.repo, 'worktree')
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('during reading', result.findings[0].message)
        self.assertEqual(path.read_text(), 'changed!')

    def test_python_aws_secret_fields_span_lines_and_annotations(self):
        secret = 'aB3/+' * 8
        literal = repr(secret)
        expressions = (
            'aws_secret_access_key = (\n' + literal + '\n)',
            'aws_secret_access_key: str = ' + literal,
            'settings.AWS_SECRET_ACCESS_KEY = (\n' + literal + '\n)',
            'if (secretaccesskey := ' + literal + '): pass',
            'client(aws_secret_access_key=(\n' + literal + '\n))',
            'values = {"aws_secret_access_key": (\n' + literal + '\n)}',
            'values = {b"SecretAccessKey": ' + repr(secret.encode()) + '}',
            'def client(ordinary, aws_secret_access_key=(\n' + literal + '\n)): pass',
            'def client(*, SecretAccessKey=(\n' + literal + '\n)): pass')
        for source in expressions:
            with self.subTest(source=source[:40]):
                self.write('fields.py', source)
                for scope in ('staged', 'worktree'):
                    result = scan(self.repo, scope)
                    self.assertEqual(result.status, 'fail', result.to_dict())
                    self.assertEqual({f.rule for f in result.findings}, {'aws-secret-key'})
                    self.assertNotIn(secret, json.dumps(result.to_dict()))

    def test_python_aws_fields_decode_adjacent_and_escaped_literals(self):
        secret = 'aB3/+' * 8
        for value in (repr(secret[:20]) + '\n' + repr(secret[20:]),
                      repr(secret).replace('a', r'\x61'), repr(secret.encode())):
            self.write('fields.py', 'aws_secret_access_key = (\n' + value + '\n)')
            result = scan(self.repo)
            self.assertEqual([(f.rule, f.line) for f in result.findings], [('aws-secret-key', 2)])

    def test_python_aws_context_does_not_classify_unrelated_strings_or_duplicate_hits(self):
        secret = 'aB3/+' * 8
        self.write('fields.py', 'aws_secret_access_key = ' + repr(secret))
        self.assertEqual(len(scan(self.repo).findings), 1)
        for source in ('ordinary = ' + repr(secret),
                       'aws_secret_access_key = "short-example"',
                       'aws_secret_access_key: str',
                       'def client(aws_secret_access_key, ordinary="value"): pass',
                       'def client(*, aws_secret_access_key): pass',
                       '{"unrelated": ' + repr(secret) + '}',
                       'client(ordinary=' + repr(secret) + ')'):
            self.write('fields.py', source)
            self.assertEqual(scan(self.repo).status, 'pass', source[:40])

    def test_plaintext_multiline_aws_assignments_report_the_value_line(self):
        secret = 'aB3/+' * 8
        for newline in ('\n', '\r\n', '\r', '\v'):
            with self.subTest(newline=repr(newline)):
                report = Report('text')
                scan_text(report, 'message', 'intro' + newline + 'aws_secret_access_key = (' +
                          newline + repr(secret) + newline + ')')
                self.assertEqual([(f.rule, f.line) for f in report.findings], [('aws-secret-key', 3)])
        for expression in ('aws_secret_access_key: str = ', 'aws_secret_access_key: bytes = b',
                           'SecretAccessKey := ', 'aws_secret_access_key = r'):
            report = Report('text')
            scan_text(report, 'message', expression + repr(secret))
            self.assertEqual([(f.rule, f.line) for f in report.findings], [('aws-secret-key', 1)])

    def test_multiline_aws_matching_preserves_lengths_and_one_finding_per_line(self):
        secret = 'A' * 40
        for source in ('aws_secret_access_key = (\n' + repr('A' * 39) + '\n)',
                       'aws_secret_access_key = (\n' + repr('A' * 41) + '\n)',
                       'aws_secret_access_key = None\nother = ' + repr(secret),
                       'unrelated = (\n' + repr(secret) + '\n)'):
            report = Report('text')
            scan_text(report, 'message', source)
            self.assertEqual(report.status, 'pass')
        report = Report('text')
        scan_text(report, 'message', 'aws_secret_access_key=' + repr(secret) +
                  '; SecretAccessKey=' + repr(secret))
        self.assertEqual(len(report.findings), 1)
