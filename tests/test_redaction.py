import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.__main__ import main
from ai_pilled.credentials import redact
from ai_pilled.lifecycle import handle
from ai_pilled.reporting import dashboard, summarize
from ai_pilled.runtime import Report
from ai_pilled.state import record


class RedactionTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.token = 'ghp_' + 'Z' * 36

    def assert_redacted(self, value):
        serialized = json.dumps(value)
        self.assertFalse(self.token in serialized, 'Credential remained in output')
        self.assertIn('[REDACTED]', serialized)

    def test_report_fields_and_stored_history_redact_credential_names(self):
        result = Report(self.token)
        result.add('problem', 'Could not read ' + self.token, path=self.token + '.txt')
        self.assert_redacted(result.to_dict())
        record(self.repo, result, 'test')
        history = (self.repo / '.ai-pilled' / 'events.jsonl').read_text()
        self.assertFalse(self.token in history)

    def test_cli_missing_executable_error_redacts_its_name(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [str(self.repo / self.token)]}}))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = main(['--repo', str(self.repo), 'check', 'test'])
        self.assertEqual(status, 2)
        self.assert_redacted(json.loads(output.getvalue()))

    def test_session_start_redacts_branch_and_file_names(self):
        subprocess.run(['git', 'init', '-q', '-b', self.token, str(self.repo)], check=True)
        (self.repo / (self.token + '.txt')).write_text('ordinary content')
        self.assert_redacted(handle(self.repo, {'hook_event_name': 'SessionStart'}))

    def test_stop_feedback_redacts_command_errors(self):
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'commands': {'test': [str(self.repo / self.token)]}}))
        self.assert_redacted(handle(self.repo, {'hook_event_name': 'Stop'}))

    def test_legacy_history_is_redacted_when_summarized_or_rendered(self):
        state = self.repo / '.ai-pilled'
        state.mkdir()
        entry = {'at': '2026-09-16T00:00:00Z', 'report': {'check': 'test', 'status': 'fail',
                 'findings': [{'message': self.token, 'path': self.token + '.txt'}]}}
        (state / 'events.jsonl').write_text(json.dumps(entry) + '\n')
        self.assert_redacted(summarize(self.repo))
        rendered = dashboard(self.repo).read_text()
        self.assertFalse(self.token in rendered)
        self.assertIn('[REDACTED]', rendered)

    def test_complete_and_unterminated_private_key_bodies_are_redacted(self):
        header = '-----BEGIN ' + 'PRIVATE KEY-----\n'
        body = 'synthetic-sensitive-key-body\n'
        footer = '-----END ' + 'PRIVATE KEY-----'
        for key in (header + body + footer, header + body):
            result = redact('Before\n' + key)
            self.assertNotIn(body.strip(), result)
            self.assertIn('[REDACTED PRIVATE KEY]', result)
            self.assertTrue(result.startswith('Before'))


    def test_aws_secret_key_assignment_is_redacted(self):
        secret = 'aB3/+' * 8
        value = 'aws_secret_access_key = "' + secret + '"'
        self.assertNotIn(secret, redact(value))
        self.assertIn('[REDACTED]', redact(value))
