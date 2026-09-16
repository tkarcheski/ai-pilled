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
from ai_pilled.credentials import redact, redact_data
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

    def test_pypi_tokens_are_redacted_from_reports_history_and_dashboard(self):
        self.token = 'pypi-' + 'Ab0_-' * 17
        result = Report('security')
        result.add('pypi-token', 'Remove ' + self.token, path=self.token + '.txt')
        self.assert_redacted(result.to_dict())
        record(self.repo, result, 'scan')
        self.assertNotIn(self.token, (self.repo / '.ai-pilled/events.jsonl').read_text())
        self.assert_redacted(summarize(self.repo))
        self.assertNotIn(self.token, dashboard(self.repo).read_text())


    def test_json_unicode_and_slash_escapes_are_redacted_without_breaking_json(self):
        values = [('ghp_' + 'A' * 36, 'g', r'\u0067'),
                  ('pypi-' + 'A' * 85, 'p', r'\u0070'),
                  ('https://hooks.slack.com/services/' + 'A' * 8 + '/' + 'B' * 8 + '/' + 'C' * 16,
                   '/', r'\/')]
        encoded = [json.dumps(value).replace(old, new) for value, old, new in values]
        document = '[' + ','.join(encoded) + ']'
        cleaned = redact(document)
        self.assertEqual(json.loads(cleaned), ['[REDACTED]'] * 3)
        result = Report('security')
        result.add('fixture', document)
        record(self.repo, result, 'fixture')
        stored = (self.repo / '.ai-pilled/events.jsonl').read_text()
        for value, _, _ in values:
            self.assertNotIn(value, stored)
        self.assertEqual(json.loads(result.to_dict()['findings'][0]['message']), ['[REDACTED]'] * 3)

    def test_encoded_private_key_body_is_fully_redacted(self):
        value = '-----BEGIN ' + 'PRIVATE KEY-----\nprivate-body\n-----END ' + 'PRIVATE KEY-----'
        encoded = json.dumps(value).replace('-', r'\u002d')
        self.assertEqual(json.loads(redact(encoded)), '[REDACTED PRIVATE KEY]')

    def test_ordinary_and_malformed_quoted_text_is_preserved(self):
        for value in ('"\\u0068ello"', '"bad\\q"', 'unquoted ordinary text'):
            self.assertEqual(redact(value), value)

    def test_non_ascii_neighbors_do_not_hide_tokens_from_redaction(self):
        for token in ('ghp_' + 'A' * 36, 'AKIA' + 'A' * 16, 'pypi-' + 'A' * 85):
            value = chr(255) + token + chr(255)
            self.assertEqual(redact(value), chr(255) + '[REDACTED]' + chr(255))

    def test_aws_json_field_redaction_preserves_structure_and_duplicate_keys(self):
        secret = 'aB3/+' * 8
        for escaped in (False, True):
            key, value = json.dumps('aws_secret_access_key'), json.dumps(secret)
            if escaped:
                key = key.replace('a', r'\u0061', 1)
                value = value.replace('a', r'\u0061', 1)
            source = '{' + key + ':' + value + ',' + key + ':"ordinary", "note":"keep"}'
            self.assertEqual(json.loads(redact(source), object_pairs_hook=list),
                             [('aws_secret_access_key', '[REDACTED]'),
                              ('aws_secret_access_key', 'ordinary'), ('note', 'keep')])

    def test_aws_fields_are_redacted_in_nested_data_and_legacy_history(self):
        secret = 'aB3/+' * 8
        data = {'items': [{'AWS_SECRET_ACCESS_KEY': secret}], 'checksum': secret,
                'SecretAccessKey': None}
        cleaned = redact_data(data)
        self.assertEqual(cleaned['items'][0]['AWS_SECRET_ACCESS_KEY'], '[REDACTED]')
        self.assertEqual(cleaned['checksum'], secret)
        self.assertIsNone(cleaned['SecretAccessKey'])
        state = self.repo / '.ai-pilled'
        state.mkdir()
        entry = {'at': '2026-09-16T00:00:00Z', 'report': {'check': 'test', 'status': 'fail',
                 'findings': [{'message': 'legacy', 'SecretAccessKey': secret}]}}
        (state / 'events.jsonl').write_text(json.dumps(entry) + '\n')
        self.assertNotIn(secret, json.dumps(summarize(self.repo)))
        self.assertNotIn(secret, dashboard(self.repo).read_text())

    def test_quoted_private_key_headers_do_not_expose_the_remaining_body(self):
        header = '-----BEGIN ' + 'PRIVATE KEY-----'
        footer = '-----END ' + 'PRIVATE KEY-----'
        source = json.dumps(header) + '\nprivate-body\n' + json.dumps(footer)
        self.assertNotIn('private-body', redact(source))

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
