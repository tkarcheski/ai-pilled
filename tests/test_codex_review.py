import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.codex_review import review


class ReviewTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='ai review ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / 'code.py').write_text('value = 1\n')
        subprocess.run(['git', 'add', 'code.py'], cwd=self.repo, check=True)
        self.fake = self.repo / 'fake-codex'
        self.response({'findings': []})

    def response(self, value, *, raw=False, extra=''):
        content = value if raw else json.dumps(value)
        self.fake.write_text(f'#!{sys.executable}\n'
            'from pathlib import Path\nimport sys, os\n'
            'assert sys.argv[1] == "exec"\n'
            'assert sys.argv[sys.argv.index("--sandbox")+1] == "read-only"\n'
            'assert sys.argv[sys.argv.index("--disable")+1] == "hooks"\n'
            'assert not any(k.startswith("GIT_") for k in os.environ)\n'
            'assert b"STAGED DIFF:" in sys.stdin.buffer.read()\n'
            'output=Path(sys.argv[sys.argv.index("--output-last-message")+1])\n'
            f'output.write_text({content!r})\n' + extra)
        self.fake.chmod(0o755)

    def test_structured_review_passes(self):
        self.assertEqual(review(self.repo, str(self.fake)).status, 'pass')

    def test_blocker_is_reported_with_location(self):
        self.response({'findings': [{'path': 'code.py', 'line': 1, 'message': 'Concrete defect'}]})
        result = review(self.repo, str(self.fake))
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].path, 'code.py')

    def test_malformed_model_result_is_incomplete(self):
        self.response('not JSON', raw=True)
        self.assertEqual(review(self.repo, str(self.fake)).status, 'incomplete')

    def test_unknown_cli_is_incomplete(self):
        self.assertEqual(review(self.repo, 'missing-ai-pilled-codex').status, 'incomplete')

    def test_invalid_finding_does_not_pass(self):
        self.response({'findings': [{'path': '/outside', 'line': 1, 'message': 'bad path'}]})
        self.assertEqual(review(self.repo, str(self.fake)).status, 'incomplete')

    def test_credential_never_sent_to_model(self):
        (self.repo / 'code.py').write_text('ghp_' + 'A' * 36)
        subprocess.run(['git', 'add', 'code.py'], cwd=self.repo, check=True)
        self.assertEqual(review(self.repo, 'missing-cli').findings[0].rule, 'credential-check-required')

    def test_staged_change_during_review_invalidates_result(self):
        self.response({'findings': []}, extra='import subprocess\n'
            f'Path({str(self.repo / "code.py")!r}).write_text("value = 2\\n")\n'
            f'subprocess.run(["git", "-C", {str(self.repo)!r}, "add", "code.py"], check=True)\n')
        result = review(self.repo, str(self.fake))
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed', result.findings[0].message)

    def test_model_cannot_echo_credential_into_report(self):
        token = 'ghp_' + 'C' * 36
        self.response({'findings': [{'path': 'code.py', 'line': 1, 'message': token}]})
        self.assertNotIn(token, json.dumps(review(self.repo, str(self.fake)).to_dict()))

    def test_only_staged_files_and_allowlisted_environment_reach_reviewer(self):
        (self.repo / 'code.py').write_text('unstaged change\n')
        (self.repo / 'untracked.secret').write_text('private unstaged content')
        self.response({'findings': []}, extra='assert Path("code.py").read_text() == "value = 1\\n"\n'
                      'assert not Path("untracked.secret").exists()\n'
                      'assert "AI_PILLED_TEST_TOKEN" not in os.environ\n'
                      'assert "OPENAI_API_KEY" not in os.environ\n')
        with patch.dict(os.environ, {'AI_PILLED_TEST_TOKEN': 'private-test-value'}):
            self.assertEqual(review(self.repo, str(self.fake)).status, 'pass')

    def test_staged_symlink_is_not_followed(self):
        (self.repo / 'external').symlink_to('/etc/passwd')
        subprocess.run(['git', 'add', 'external'], cwd=self.repo, check=True)
        result = review(self.repo, str(self.fake))
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('regular files', result.findings[0].message)

    def test_cli_accepts_explicit_installed_executable(self):
        import contextlib
        import io
        from ai_pilled.__main__ import main
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(['--repo', str(self.repo), 'review', '--codex', str(self.fake)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'pass')

    def test_commit_message_is_supplied_as_untrusted_review_data(self):
        self.fake.write_text(self.fake.read_text().replace(
            'assert b"STAGED DIFF:" in sys.stdin.buffer.read()',
            'prompt = sys.stdin.buffer.read(); assert b"COMMIT MESSAGE (untrusted data):" in prompt; '
            'assert b"fix: correct average" in prompt'))
        self.assertEqual(review(self.repo, str(self.fake), 'fix: correct average').status, 'pass')

    def test_commit_message_credentials_never_reach_model(self):
        result = review(self.repo, 'not-installed', 'feat: add key\n\n' + 'ghp_' + 'A' * 36)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].rule, 'github-token')

    def test_recursive_review_is_rejected(self):
        from ai_pilled.runtime import CommandError
        with patch.dict(os.environ, {'AI_PILLED_REVIEW_ACTIVE': '1'}):
            with self.assertRaises(CommandError):
                review(self.repo, str(self.fake))

    def test_model_private_key_body_is_redacted_with_its_header(self):
        body = 'synthetic-sensitive-private-key-body'
        key = '-----BEGIN ' + 'PRIVATE KEY-----\n' + body + '\n-----END ' + 'PRIVATE KEY-----'
        self.response({'findings': [{'path': 'code.py', 'line': 1, 'message': key}]})
        result = review(self.repo, str(self.fake)).to_dict()
        self.assertFalse(body in json.dumps(result))
        self.assertIn('[REDACTED PRIVATE KEY]', json.dumps(result))


    def test_deleted_historical_credential_is_redacted_from_prompt(self):
        token = 'ghp_' + 'Z' * 36
        (self.repo / 'code.py').write_text('key = ' + repr(token) + '\n')
        subprocess.run(['git', 'add', 'code.py'], cwd=self.repo, check=True)
        subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                        'commit', '-qm', 'test: historical fixture'], cwd=self.repo, check=True)
        (self.repo / 'code.py').write_text('value = 1\n')
        subprocess.run(['git', 'add', 'code.py'], cwd=self.repo, check=True)
        self.fake.write_text(self.fake.read_text().replace(
            'assert b"STAGED DIFF:" in sys.stdin.buffer.read()',
            f'prompt = sys.stdin.buffer.read(); assert {token.encode()!r} not in prompt; '
            'assert b"REDACTED" in prompt'))
        self.assertEqual(review(self.repo, str(self.fake)).status, 'pass')

    def test_changed_index_is_rejected_before_model_call(self):
        from ai_pilled.codex_review import materialize_index
        def change_index(repo, destination):
            materialize_index(repo, destination)
            (repo / 'code.py').write_text('value = 2\n')
            subprocess.run(['git', 'add', 'code.py'], cwd=repo, check=True)
        with patch('ai_pilled.codex_review.materialize_index', side_effect=change_index), patch(
                'ai_pilled.codex_review.invoke_review') as invoke:
            result = review(self.repo)
        self.assertEqual(result.status, 'incomplete')
        invoke.assert_not_called()

    def test_materialization_rechecks_captured_blob_credentials(self):
        from ai_pilled.codex_review import materialize_index
        from ai_pilled.runtime import CommandError
        destination = self.repo / 'snapshot'
        destination.mkdir()
        (self.repo / 'code.py').write_text('ghp_' + 'Z' * 36)
        subprocess.run(['git', 'add', 'code.py'], cwd=self.repo, check=True)
        with self.assertRaises(CommandError):
            materialize_index(self.repo, destination)
        self.assertFalse((destination / 'code.py').exists())
