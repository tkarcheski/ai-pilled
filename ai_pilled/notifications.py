"""Explicit, preview-first delivery of minimal historical check digests."""
from dataclasses import dataclass
from email.message import EmailMessage
import http.client
import json
import os
import re
import smtplib
import ssl
from urllib.parse import urlsplit
import uuid

from .reporting import summarize
from .runtime import CommandError, Report
from .security import scan_text


@dataclass
class NotificationReport(Report):
    preview: str = ''
    delivery: str = 'not-sent'
    target: str = ''


def digest(repo):
    summary = summarize(repo)
    lines = ['ai-pilled check digest', summary['summary'], summary['evidence'],
             'Next: ' + summary['next']]
    # Deliberately omit finding text, paths, command output, and source snippets.
    for entry in summary['latest']:
        check = entry['report']['check']
        if not re.fullmatch(r'[a-zA-Z0-9:_-]{1,80}', check):
            raise CommandError('History contains an invalid check name')
        lines.append(check + ': ' + entry['report']['status'])
    body = '\n'.join(lines)
    scanned = Report('notification-content')
    scan_text(scanned, 'digest', body)
    if scanned.status != 'pass' or len(body.encode()) > 12000:
        raise CommandError('Digest exceeds the content policy or size limit')
    return body


def secret(name):
    value = os.environ.get(name, '')
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CommandError('Set a valid ' + name + ' environment variable')
    return value


def post(url, payload, headers):
    """TLS only, bounded response, no redirects, no retries or raw diagnostics."""
    target = urlsplit(url)
    if target.scheme != 'https' or target.username or target.password or target.fragment:
        raise CommandError('Invalid delivery endpoint')
    connection = http.client.HTTPSConnection(target.hostname, target.port or 443,
                                              timeout=20, context=ssl.create_default_context())
    try:
        path = target.path + ('?' + target.query if target.query else '')
        connection.request('POST', path, json.dumps(payload).encode(),
                           {'Content-Type': 'application/json', 'User-Agent': 'ai-pilled', **headers})
        response = connection.getresponse()
        content = response.read(65537)
        if len(content) > 65536:
            raise CommandError('Delivery response exceeds size limit; verify the destination before retrying')
        return response.status, content
    finally:
        connection.close()


def address(value):
    if not re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', value or ''):
        raise CommandError('Use a plain sender and recipient email address')
    return value


def email_digest(body, sender, recipient):
    host = secret('AI_PILLED_SMTP_HOST')
    if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
        raise CommandError('Invalid SMTP host')
    try:
        port = int(os.environ.get('AI_PILLED_SMTP_PORT', '465'))
    except ValueError as exc:
        raise CommandError('Invalid SMTP port') from exc
    if not 1 <= port <= 65535:
        raise CommandError('Invalid SMTP port')
    username, password = secret('AI_PILLED_SMTP_USER'), secret('AI_PILLED_SMTP_PASSWORD')
    message = EmailMessage()
    message['From'], message['To'] = address(sender), address(recipient)
    message['Subject'] = 'ai-pilled check digest'
    message.set_content(body)
    with smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context()) as client:
        client.login(username, password)
        if client.send_message(message):
            raise CommandError('SMTP rejected a recipient; delivery not confirmed')


def notify(repo, provider, *, send=False, github_repo=None, issue=None, team=None,
           sender=None, recipient=None):
    report = NotificationReport('notification')
    try:
        if provider not in ('slack', 'linear', 'github', 'email'):
            raise CommandError('Unsupported notification provider')
        body = digest(repo)
        if provider == 'github':
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', github_repo or '') or (github_repo or '').split('/')[-1] in ('.', '..') or type(issue) is not int or issue < 1:
                raise CommandError('Select a GitHub owner/repository and positive issue or PR number')
        elif provider == 'linear':
            try:
                uuid.UUID(team or '')
            except ValueError as exc:
                raise CommandError('Select a Linear team UUID') from exc
        elif provider == 'email':
            address(sender)
            address(recipient)
        report.target = (f'{github_repo}#{issue}' if provider == 'github' else
                         team if provider == 'linear' else recipient if provider == 'email' else
                         'Channel configured by AI_PILLED_SLACK_WEBHOOK')
        report.preview = body
        if not send:
            report.delivery = 'preview'
            return report
        if provider == 'email':
            email_digest(body, sender, recipient)
        else:
            headers = {}
            if provider == 'slack':
                endpoint = secret('AI_PILLED_SLACK_WEBHOOK')
                if not re.fullmatch(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+', endpoint):
                    raise CommandError('Use a Slack incoming webhook HTTPS endpoint')
                payload = {'text': body, 'unfurl_links': False, 'unfurl_media': False}
            elif provider == 'github':
                endpoint = f'https://api.github.com/repos/{github_repo}/issues/{issue}/comments'
                headers = {'Authorization': 'Bearer ' + secret('AI_PILLED_GITHUB_TOKEN'),
                           'Accept': 'application/vnd.github+json'}
                payload = {'body': body}
            else:
                endpoint = 'https://api.linear.app/graphql'
                headers = {'Authorization': secret('AI_PILLED_LINEAR_KEY')}
                payload = {'query': 'mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id } } }',
                           'variables': {'input': {'teamId': team, 'title': 'ai-pilled check digest',
                                                   'description': body}}}
            status, raw = post(endpoint, payload, headers)
            if provider == 'slack':
                confirmed = status == 200 and raw.strip() == b'ok'
            else:
                data = json.loads(raw)
                if provider == 'github':
                    confirmed = status == 201 and isinstance(data, dict) and type(data.get('id')) is int and data['id'] > 0
                else:
                    created = data.get('data', {}).get('issueCreate', {}) if isinstance(data, dict) and isinstance(data.get('data'), dict) else {}
                    confirmed = status == 200 and not data.get('errors') and isinstance(created, dict) and created.get('success') is True and bool(created.get('issue', {}).get('id'))
            if not confirmed:
                raise CommandError('Delivery was not confirmed; inspect the destination before retrying')
        report.delivery = 'accepted'
        report.metrics = {'accepted': 1}
    except (CommandError, OSError, ValueError, TypeError, AttributeError, http.client.HTTPException, smtplib.SMTPException) as exc:
        report.add('notification-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Delivery unavailable or response invalid; inspect the destination before retrying', severity='warning')
        if send:
            report.delivery = 'unconfirmed'
    return report
