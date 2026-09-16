import os
from unittest.mock import patch
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ai_pilled.git_hooks import install
from ai_pilled.pre_push import pre_push


class PrePushTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='ai-pilled push ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'work'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        self.configure(0)
        self.commit()
        self.remote = Path(self.temp.name) / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(self.remote)], check=True)
        self.git('remote', 'add', 'origin', str(self.remote))

    def git(self, *args, success=True):
        result = subprocess.run(['git', *args], cwd=self.repo, capture_output=True)
        if success and result.returncode:
            self.fail(result.stderr.decode())
        return result

    def configure(self, code):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'commands': {'test': [sys.executable, '-c', f'raise SystemExit({code})']}}))

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'test: fixture')

    def update(self, branch='feature', old=None):
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        return f'refs/heads/feature {head} refs/heads/{branch} {old or "0" * 40}\n'

    def test_actual_push_to_feature_succeeds(self):
        install(self.repo)
        self.git('push', 'origin', 'HEAD:feature')
        remote_head = subprocess.check_output(['git', '--git-dir', str(self.remote),
                                              'rev-parse', 'refs/heads/feature'])
        self.assertEqual(remote_head, self.git('rev-parse', 'HEAD').stdout)

    def test_actual_push_to_protected_branch_fails(self):
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:main', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'protected-branch', result.stdout + result.stderr)
        self.assertEqual(subprocess.check_output(['git', '--git-dir', str(self.remote),
                                                'for-each-ref']), b'')

    def test_failed_tests_block_actual_push(self):
        self.configure(1)
        self.commit()
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:feature', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'command-failed', result.stdout + result.stderr)
        self.assertEqual(subprocess.check_output(['git', '--git-dir', str(self.remote),
                                                'for-each-ref']), b'')

    def test_hidden_local_fix_cannot_authorize_broken_commit_push(self):
        (self.repo / 'value.txt').write_text('broken')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [
            sys.executable, '-c', 'from pathlib import Path; assert Path("value.txt").read_text() == "correct"']}}))
        self.commit()
        install(self.repo)
        for flag, clear in (('--assume-unchanged', '--no-assume-unchanged'),
                            ('--skip-worktree', '--no-skip-worktree')):
            with self.subTest(flag=flag):
                self.git('update-index', flag, 'value.txt')
                (self.repo / 'value.txt').write_text('correct')
                self.assertEqual(self.git('status', '--porcelain').stdout, b'')
                result = self.git('push', 'origin', 'HEAD:feature', success=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'hidden-worktree', result.stdout + result.stderr)
                self.assertEqual(subprocess.check_output(['git', '--git-dir', str(self.remote),
                                                         'for-each-ref']), b'')
                self.git('update-index', clear, 'value.txt')
                (self.repo / 'value.txt').write_text('broken')

    def test_hidden_mutation_during_tests_cannot_authorize_push(self):
        (self.repo / 'value.txt').write_text('before')
        program = ('import subprocess; from pathlib import Path; '
                   'subprocess.run(["git", "update-index", "--assume-unchanged", "value.txt"], check=True); '
                   'Path("value.txt").write_text("after")')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [sys.executable, '-c', program]}}))
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('test-snapshot-changed', [f.rule for f in result.findings])
        self.assertEqual(self.git('status', '--porcelain').stdout, b'')

    def test_hidden_policy_cannot_disable_test_gate(self):
        self.git('update-index', '--assume-unchanged', '.ai-pilled.json')
        (self.repo / '.ai-pilled.json').write_text('{"require_tests":false}')
        self.assertEqual(pre_push(self.repo, self.update()).status, 'fail')

    def test_secret_removed_in_later_commit_still_blocks(self):
        (self.repo / 'credential').write_text('ghp_' + 'A' * 36)
        self.commit()
        (self.repo / 'credential').unlink()
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('github-token', [f.rule for f in result.findings])

    def test_dirty_worktree_blocks_false_test_evidence(self):
        (self.repo / 'new.py').write_text('print("uncommitted")')
        result = pre_push(self.repo, self.update())
        self.assertIn('dirty-worktree', [f.rule for f in result.findings])

    def test_non_head_push_cannot_borrow_head_tests(self):
        old = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        (self.repo / 'file').write_text('next')
        self.commit()
        result = pre_push(self.repo, f'old {old} refs/heads/other {"0" * 40}\n')
        self.assertIn('untested-tip', [f.rule for f in result.findings])

    def test_only_outgoing_commits_are_scanned_when_old_tip_is_known(self):
        (self.repo / 'credential').write_text('ghp_' + 'B' * 36)
        self.commit()
        old = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        (self.repo / 'credential').unlink()
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update(old=old)).status, 'pass')

    def test_malformed_input_fails(self):
        self.assertEqual(pre_push(self.repo, 'not valid').status, 'fail')

    def test_test_command_cannot_mutate_files_and_still_authorize_push(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [
            sys.executable, '-c', 'from pathlib import Path; Path("changed.py").write_text("changed")']}}))
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('test-snapshot-changed', [f.rule for f in result.findings])

    def test_test_command_cannot_switch_to_a_new_clean_commit(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [
            'git', 'commit', '--allow-empty', '-qm', 'test: changed head']}}))
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertIn('test-snapshot-changed', [f.rule for f in result.findings])

    def test_outgoing_commit_message_credentials_are_scanned(self):
        self.git('commit', '--allow-empty', '-qm', 'feat: safe subject\n\n' + 'ghp_' + 'A' * 36)
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'github-token' and f.path == '(commit message)' for f in result.findings))

    def test_strict_patterns_check_tip_but_allow_fixed_historical_code(self):
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['aggressiveness'] = 'strict'
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        (self.repo / 'parse.py').write_text('eval(data)\n')
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update()).status, 'fail')
        (self.repo / 'parse.py').write_text('value = 1\n')
        self.commit()
        self.assertEqual(pre_push(self.repo, self.update()).status, 'pass')

    def test_unchanged_blobs_are_read_once_across_outgoing_commits(self):
        from ai_pilled.runtime import run
        for number in range(4):
            self.git('commit', '--allow-empty', '-qm', f'test: unchanged tree {number}')
        with patch('ai_pilled.pre_push.run', wraps=run) as commands:
            result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'pass')
        blob_calls = [call.args[0] for call in commands.call_args_list
                      if call.args[0][:3] == ['git', 'cat-file', 'blob']]
        blobs = {line.split()[2] for line in self.git('ls-tree', '-r', 'HEAD').stdout.splitlines()}
        self.assertEqual(len(blob_calls), len(blobs))

    def test_cache_preserves_locations_and_never_stores_secret_bytes(self):
        from ai_pilled.pre_push import scan_revision
        token = 'ghp_' + 'A' * 36
        (self.repo / 'first.txt').write_text(token)
        (self.repo / 'second.txt').write_text(token)
        self.commit()
        cache = {}
        result = scan_revision(self.repo, 'HEAD', cache=cache)
        self.assertEqual({f.path for f in result.findings}, {'first.txt', 'second.txt'})
        self.assertNotIn(token, str(cache))
        self.assertEqual(scan_revision(self.repo, 'HEAD', cache=cache).to_dict(), result.to_dict())

    def test_cache_separates_python_inspection_from_plain_credential_scan(self):
        from ai_pilled.pre_push import scan_revision
        (self.repo / 'example.txt').write_text('eval(data)\n')
        (self.repo / 'example.py').write_text('eval(data)\n')
        self.commit()
        cache = {}
        self.assertEqual(scan_revision(self.repo, 'HEAD', cache=cache).status, 'pass')
        result = scan_revision(self.repo, 'HEAD', patterns=True, cache=cache)
        self.assertEqual([f.path for f in result.findings], ['example.py'])

    def test_full_cache_still_scans_uncached_blobs(self):
        from ai_pilled.pre_push import scan_revision
        (self.repo / 'secret.txt').write_text('ghp_' + 'B' * 36)
        self.commit()
        cache = {}
        with patch('ai_pilled.pre_push.MAX_CACHE_ENTRIES', 1):
            result = scan_revision(self.repo, 'HEAD', cache=cache)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(len(cache), 1)

    def test_destination_ref_credentials_block_updates_but_allow_deletion(self):
        token = 'ghp_' + 'Z' * 36
        result = pre_push(self.repo, self.update(branch=token))
        self.assertEqual(result.status, 'fail')
        self.assertFalse(token in json.dumps(result.to_dict()))
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        deletion = f'(delete) {"0" * 40} refs/heads/{token} {head}\n'
        self.assertEqual(pre_push(self.repo, deletion).status, 'pass')

    def test_commit_author_credentials_block_push(self):
        token = 'ghp_' + 'Z' * 36
        self.git('commit', '--allow-empty', '--author', token + ' <test@example.invalid>',
                 '-qm', 'test: author metadata')
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == '(commit identity)' for f in result.findings))
        self.assertFalse(token in json.dumps(result.to_dict()))

    def test_committed_file_name_credentials_block_push(self):
        token = 'ghp_' + 'Z' * 36
        (self.repo / (token + '.txt')).write_text('ordinary')
        self.commit()
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertFalse(token in json.dumps(result.to_dict()))

    def test_nested_annotated_tag_credentials_block_push(self):
        token = 'ghp_' + 'Z' * 36
        self.git('tag', '-a', 'inner', '-m', token)
        self.git('tag', '-a', 'outer', 'inner', '-m', 'clean outer annotation')
        oid = self.git('rev-parse', 'refs/tags/outer').stdout.decode().strip()
        result = pre_push(self.repo, f'refs/tags/outer {oid} refs/tags/outer {"0" * 40}\n')
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == '(tag metadata)' for f in result.findings))
        self.assertFalse(token in json.dumps(result.to_dict()))

    def test_clean_annotated_tag_can_be_pushed(self):
        self.git('tag', '-a', 'v1.0.0', '-m', 'Release annotation')
        oid = self.git('rev-parse', 'refs/tags/v1.0.0').stdout.decode().strip()
        self.assertEqual(pre_push(self.repo, f'tag {oid} refs/tags/v1.0.0 {"0" * 40}\n').status, 'pass')


    def test_additional_commit_headers_are_scanned(self):
        token = 'ghp_' + 'Z' * 36
        original = self.git('cat-file', 'commit', 'HEAD').stdout
        content = original.replace(b'\n\n', b'\nx-ai-pilled ' + token.encode() + b'\n\n', 1)
        written = subprocess.run(['git', 'hash-object', '-t', 'commit', '-w', '--stdin'],
                                 cwd=self.repo, input=content, capture_output=True, check=True)
        self.git('update-ref', 'HEAD', written.stdout.decode().strip())
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == '(commit headers)' for f in result.findings))
        self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_replaced_commit_cannot_hide_outgoing_credentials(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'require_tests': False}))
        self.commit()
        clean = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        token = 'ghp_' + 'R' * 36
        (self.repo / 'credential.txt').write_text(token)
        self.commit()
        unsafe = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git('replace', unsafe, clean)
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.path == 'credential.txt' for f in result.findings))
        self.assertNotIn(token, json.dumps(result.to_dict()))

    def test_actual_push_rejects_nonconventional_outgoing_history(self):
        self.git('commit', '--allow-empty', '-qm', 'unreviewed imported change')
        self.git('commit', '--allow-empty', '-qm', 'fix: conventional tip')
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:feature', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'conventional-commit', result.stdout + result.stderr)
        self.assertEqual(subprocess.check_output(['git', '--git-dir', str(self.remote),
                                                 'for-each-ref']), b'')

    def test_outgoing_subject_length_is_enforced(self):
        self.git('commit', '--allow-empty', '-qm', 'fix: ' + 'x' * 70)
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'subject-length' for f in result.findings))

    def test_existing_remote_conventions_do_not_block_valid_new_commits(self):
        self.git('commit', '--allow-empty', '-qm', 'legacy remote subject')
        old = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git('commit', '--allow-empty', '-qm', 'fix: follow current conventions')
        self.assertEqual(pre_push(self.repo, self.update(old=old)).status, 'pass')

    def test_new_branch_excludes_verified_published_legacy_ancestry(self):
        self.git('commit', '--allow-empty', '-qm', 'legacy published subject')
        self.git('push', 'origin', 'HEAD:existing')
        self.git('commit', '--allow-empty', '-qm', 'feat: reviewed new branch')
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:new-branch', success=False)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())

    def test_forged_remote_tracking_ref_does_not_hide_unpublished_commit(self):
        self.git('push', 'origin', 'HEAD:existing')
        self.git('commit', '--allow-empty', '-qm', 'unpublished bad subject')
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git('update-ref', 'refs/remotes/origin/forged', head)
        self.git('commit', '--allow-empty', '-qm', 'feat: reviewed tip')
        install(self.repo)
        result = self.git('push', 'origin', 'HEAD:new-branch', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'conventional-commit', result.stdout + result.stderr)

    def test_new_branch_remote_evidence_is_bounded_and_failure_blocks(self):
        from ai_pilled.pre_push import published_commits
        from ai_pilled.runtime import CommandError
        with self.assertRaises(CommandError):
            published_commits(self.repo, str(self.remote / 'missing'))
        for output in (b'not-a-ref\n', b'0' * 40 + b'\trefs/other/invalid\n'):
            with patch('ai_pilled.pre_push.run', return_value=output), self.assertRaises(CommandError):
                published_commits(self.repo, 'origin')
        self.git('push', 'origin', 'HEAD:existing')
        with patch('ai_pilled.pre_push.MAX_REMOTE_REFS', 0), self.assertRaises(CommandError):
            published_commits(self.repo, str(self.remote))
        result = pre_push(self.repo, self.update(), destination=str(self.remote / 'missing'))
        self.assertNotEqual(result.status, 'pass')

    def test_published_tip_still_receives_security_scan(self):
        token = 'ghp_' + 'Z' * 36
        (self.repo / 'secret').write_text(token)
        self.commit()
        self.git('push', 'origin', 'HEAD:existing')
        result = pre_push(self.repo, self.update(), destination=str(self.remote))
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'github-token' for f in result.findings))

    def test_remote_tag_ancestry_is_verified_without_local_tracking_refs(self):
        self.git('commit', '--allow-empty', '-qm', 'legacy tagged subject')
        self.git('tag', '-a', 'v0', '-m', 'old published release')
        self.git('push', 'origin', 'refs/tags/v0')
        self.git('commit', '--allow-empty', '-qm', 'feat: next proposal')
        install(self.repo)
        self.git('push', 'origin', 'HEAD:proposal')

    def test_legacy_grafts_cannot_hide_removed_outgoing_credentials(self):
        (self.repo / 'credential').write_text('ghp_' + 'Z' * 36)
        self.commit()
        (self.repo / 'credential').unlink()
        self.commit()
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        graft = self.repo / '.git/info/grafts'
        graft.write_text(head + '\n')
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'github-token' for f in result.findings))
        self.assertEqual(graft.read_text(), head + '\n')

    def test_inherited_graft_file_cannot_hide_removed_outgoing_credentials(self):
        (self.repo / 'credential').write_text('ghp_' + 'Z' * 36)
        self.commit()
        (self.repo / 'credential').unlink()
        self.commit()
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        graft = self.repo / '.git/custom-grafts'
        graft.write_text(head + '\n')
        with patch.dict(os.environ, {'GIT_GRAFT_FILE': str(graft)}):
            result = pre_push(self.repo, self.update())
            self.assertEqual(os.environ['GIT_GRAFT_FILE'], str(graft))
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(f.rule == 'github-token' for f in result.findings))

    def test_shallow_boundary_cannot_claim_complete_outgoing_history(self):
        (self.repo / 'credential').write_text('ghp_' + 'Z' * 36)
        self.commit()
        (self.repo / 'credential').unlink()
        self.commit()
        head = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        shallow = self.repo / '.git/shallow'
        shallow.write_text(head + '\n')
        result = pre_push(self.repo, self.update())
        self.assertEqual(result.status, 'incomplete', result.to_dict())
        self.assertTrue(any(f.rule == 'history-incomplete' for f in result.findings))
        self.assertEqual(shallow.read_text(), head + '\n')

    def test_shallow_published_boundary_allows_complete_new_range(self):
        self.git('commit', '--allow-empty', '-qm', 'legacy published boundary')
        boundary = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git('push', 'origin', 'HEAD:existing')
        (self.repo / '.git/shallow').write_text(boundary + '\n')
        self.git('commit', '--allow-empty', '-qm', 'feat: complete new range')
        self.assertEqual(pre_push(self.repo, self.update(old=boundary)).status, 'pass')
        self.assertEqual(pre_push(self.repo, self.update(), destination=str(self.remote)).status, 'pass')

    def test_merge_parent_evidence_is_complete(self):
        self.git('checkout', '-qb', 'side')
        (self.repo / 'side.txt').write_text('side\n')
        self.commit()
        self.git('checkout', '-q', 'feature')
        (self.repo / 'main.txt').write_text('main\n')
        self.commit()
        self.git('merge', '--no-ff', 'side', '-m', 'test: merge fixture')
        self.assertEqual(pre_push(self.repo, self.update()).status, 'pass')

    def test_oversized_update_protocol_is_rejected_before_git_or_registry_work(self):
        from ai_pilled.pre_push import MAX_UPDATE_CHARACTERS, MAX_UPDATES
        zero = '0' * 40
        deletion = f'(delete) {zero} refs/heads/feature {zero}\n'
        for updates in ('x' * (MAX_UPDATE_CHARACTERS + 1), deletion * (MAX_UPDATES + 1), None):
            with self.subTest(kind=type(updates).__name__):
                with patch('ai_pilled.pre_push.run') as command, patch('ai_pilled.pre_push.load') as config:
                    result = pre_push(self.repo, updates)
                self.assertEqual(result.status, 'incomplete')
                command.assert_not_called()
                config.assert_not_called()
        self.assertEqual(pre_push(self.repo, deletion * MAX_UPDATES).status, 'pass')

    def test_hook_reader_stops_at_the_input_limit_without_echoing_payload(self):
        import io
        from ai_pilled.git_hooks import dispatch
        from ai_pilled.pre_push import MAX_UPDATE_CHARACTERS
        from ai_pilled.runtime import CommandError
        stream = io.StringIO('x' * (MAX_UPDATE_CHARACTERS + 2))
        with patch('ai_pilled.git_hooks.sys.stdin', stream), patch('ai_pilled.pre_push.pre_push') as validate:
            with self.assertRaises(CommandError) as failure:
                dispatch(self.repo, 'pre-push', [])
        self.assertEqual(stream.tell(), MAX_UPDATE_CHARACTERS + 1)
        validate.assert_not_called()
        self.assertNotIn('x' * 20, str(failure.exception))

    def test_invalid_pre_push_cli_input_returns_protocol_error(self):
        from ai_pilled.pre_push import MAX_UPDATE_CHARACTERS
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                   PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8:strict')
        for payload in (b'x' * (MAX_UPDATE_CHARACTERS + 1), bytes([255])):
            with self.subTest(size=len(payload)):
                result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo),
                                         'hook', 'pre-push', 'origin', str(self.remote)],
                                        cwd=self.repo, env=env, input=payload,
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)['status'], 'error')
                self.assertNotIn(b'x' * 20, result.stdout + result.stderr)
                self.assertNotIn(b'Traceback', result.stderr)
                self.assertEqual(subprocess.check_output(['git', '--git-dir', str(self.remote), 'for-each-ref']), b'')
