import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ai_pilled.notifications import notify, post
from ai_pilled.runtime import Report
from ai_pilled.state import record


class NotificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        result = Report('test')
        result.add('failure', 'PRIVATE source detail', path='/private/location')
        record(self.repo, result, 'test')
        self.env = patch.dict(os.environ, {
            'AI_PILLED_SLACK_WEBHOOK': 'https://hooks.slack.com/services/FAKE/ONLY/TEST',
            'AI_PILLED_GITHUB_TOKEN': 'fake-token', 'AI_PILLED_LINEAR_KEY': 'fake-key',
            'AI_PILLED_SMTP_HOST': 'smtp.example.invalid',
            'AI_PILLED_SMTP_USER': 'fake-user', 'AI_PILLED_SMTP_PASSWORD': 'fake-password'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_preview_never_accesses_transport_or_credentials(self):
        for provider, options in [('slack', {}), ('github', {'github_repo': 'a/b', 'issue': 2}),
                ('linear', {'team': '00000000-0000-0000-0000-000000000001'}),
                ('email', {'sender': 'sender@example.invalid', 'recipient': 'to@example.invalid'})]:
            with patch('ai_pilled.notifications.post') as http, patch('ai_pilled.notifications.email_digest') as email, patch.dict(os.environ, {}, clear=True):
                result = notify(self.repo, provider, **options)
            self.assertEqual(result.status, 'pass', result.to_dict())
            self.assertEqual(result.delivery, 'preview')
            self.assertIn('test: fail', result.preview)
            self.assertIn('Historical results only', result.preview)
            self.assertNotIn('PRIVATE', result.preview)
            self.assertNotIn('/private', result.preview)
            http.assert_not_called()
            email.assert_not_called()

    def test_slack_success_and_non_ok_response(self):
        with patch('ai_pilled.notifications.post', return_value=(200, b'ok')) as send:
            self.assertEqual(notify(self.repo, 'slack', send=True).delivery, 'accepted')
            self.assertIn('text', send.call_args.args[1])
        with patch('ai_pilled.notifications.post', return_value=(200, b'PRIVATE error')):
            result = notify(self.repo, 'slack', send=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn('PRIVATE', str(result.to_dict()))

    def test_github_comment_has_explicit_target_and_body(self):
        with patch('ai_pilled.notifications.post', return_value=(201, b'{"id":42}')) as send:
            result = notify(self.repo, 'github', send=True, github_repo='owner/repo', issue=12)
        self.assertEqual(result.delivery, 'accepted')
        url, payload, headers = send.call_args.args
        self.assertEqual(url, 'https://api.github.com/repos/owner/repo/issues/12/comments')
        self.assertEqual(headers['Authorization'], 'Bearer fake-token')
        self.assertEqual(payload['body'], result.preview)

    def test_linear_graphql_errors_are_not_success(self):
        for data, expected in [({'data': {'issueCreate': {'success': True, 'issue': {'id': 'id'}}}}, 'pass'),
                               ({'errors': [{'message': 'PRIVATE'}]}, 'incomplete'),
                               ({'data': None}, 'incomplete'),
                               ({'data': {'issueCreate': None}}, 'incomplete')]:
            with patch('ai_pilled.notifications.post', return_value=(200, json.dumps(data).encode())) as send:
                result = notify(self.repo, 'linear', send=True, team='00000000-0000-0000-0000-000000000001')
            self.assertEqual(result.status, expected, result.to_dict())
            self.assertNotIn('PRIVATE', str(result.to_dict()))
            self.assertEqual(send.call_args.args[1]['variables']['input']['description'], result.preview)

    def test_invalid_targets_and_header_injection_never_send(self):
        for provider, options in [('github', {'github_repo': '../bad/path', 'issue': 1}),
                                 ('github', {'github_repo': 'a/b', 'issue': 0}),
                                 ('linear', {'team': 'bad'}),
                                 ('email', {'sender': 'x@example.com\nBcc: other@example.com', 'recipient': 'to@example.com'})]:
            with patch('ai_pilled.notifications.post') as send, patch('ai_pilled.notifications.email_digest') as email:
                self.assertEqual(notify(self.repo, provider, send=True, **options).status, 'incomplete')
            send.assert_not_called()
            email.assert_not_called()
        with patch.dict(os.environ, {'AI_PILLED_SLACK_WEBHOOK': 'https://attacker.invalid/services/a/b/c'}), patch('ai_pilled.notifications.post') as send:
            self.assertEqual(notify(self.repo, 'slack', send=True).status, 'incomplete')
            send.assert_not_called()

    def test_missing_secret_and_network_errors_are_redacted_without_retry(self):
        with patch.dict(os.environ, {}, clear=True), patch('ai_pilled.notifications.post') as send:
            self.assertEqual(notify(self.repo, 'slack', send=True).status, 'incomplete')
            send.assert_not_called()
        with patch('ai_pilled.notifications.post', side_effect=OSError('PRIVATE token')) as send:
            result = notify(self.repo, 'slack', send=True)
        self.assertEqual(result.delivery, 'unconfirmed')
        self.assertNotIn('PRIVATE', str(result.to_dict()))
        self.assertEqual(send.call_count, 1)

    def test_email_uses_tls_login_and_plain_digest(self):
        with patch('ai_pilled.notifications.smtplib.SMTP_SSL') as smtp:
            client = smtp.return_value.__enter__.return_value
            client.send_message.return_value = {}
            result = notify(self.repo, 'email', send=True, sender='a@example.invalid', recipient='b@example.invalid')
        self.assertEqual(result.delivery, 'accepted')
        self.assertEqual(smtp.call_args.args, ('smtp.example.invalid', 465))
        self.assertEqual(smtp.call_args.kwargs['timeout'], 20)
        client.login.assert_called_once_with('fake-user', 'fake-password')
        message = client.send_message.call_args.args[0]
        self.assertEqual(message['To'], 'b@example.invalid')
        self.assertNotIn('PRIVATE', message.get_content())

    def test_http_transport_does_not_follow_redirects(self):
        with patch('ai_pilled.notifications.http.client.HTTPSConnection') as connection:
            response = MagicMock(status=302)
            response.read.return_value = b'redirect'
            connection.return_value.getresponse.return_value = response
            self.assertEqual(post('https://api.example.invalid/path', {'body': 'text'}, {}), (302, b'redirect'))
        self.assertEqual(connection.call_count, 1)
        response.read.assert_called_once_with(65537)
        connection.return_value.close.assert_called_once()

    def test_untrusted_history_cannot_insert_credentials_or_mentions(self):
        for name in ['ghp_' + 'A' * 36, '<!channel>']:
            record(self.repo, Report(name), 'test')
            with patch('ai_pilled.notifications.post') as send:
                result = notify(self.repo, 'slack', send=True)
            self.assertEqual(result.status, 'incomplete')
            self.assertFalse(result.preview)
            send.assert_not_called()


    def test_linear_requires_a_string_issue_identifier_to_confirm_delivery(self):
        for identifier in (True, 42, ['id'], {'id': 'nested'}, '', '   ', None):
            with self.subTest(identifier=identifier):
                data = {'data': {'issueCreate': {'success': True, 'issue': {'id': identifier}}}}
                with patch('ai_pilled.notifications.post', return_value=(200, json.dumps(data).encode())):
                    result = notify(self.repo, 'linear', send=True,
                                    team='00000000-0000-0000-0000-000000000001')
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.delivery, 'unconfirmed')


    def test_excessively_nested_provider_response_is_unconfirmed(self):
        nested = b'[' * 1500 + b'0' + b']' * 1500
        with patch('ai_pilled.notifications.post', return_value=(201, nested)):
            result = notify(self.repo, 'github', send=True, github_repo='owner/repo', issue=1)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.delivery, 'unconfirmed')
