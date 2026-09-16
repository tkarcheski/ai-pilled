"""Codex command-hook protocol, independently testable without a model call."""
import json
import re
from pathlib import Path

from .checks import command_check
from .credentials import redact_data
from .config import load
from .dependencies import audit_changed
from .runtime import CommandError, Report, run
from .security import scan
from .state import record


def context(event, text):
    return {'hookSpecificOutput': {'hookEventName': event, 'additionalContext': text}}


def handle(repo, payload):
    return redact_data(_handle(repo, payload))


def _handle(repo, payload):
    if not isinstance(payload, dict):
        raise CommandError('Hook input must be a JSON object')
    event = payload.get('hook_event_name')
    root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    if event == 'SessionStart':
        status = run(['git', 'status', '--short'], root).decode(errors='replace')
        try:
            branch = run(['git', 'symbolic-ref', '--short', 'HEAD'], root).decode().strip()
        except CommandError:
            branch = '(detached)'
        report = Report('session-state')
        record(root, report, event)
        return context(event, 'ai-pilled repository state (data, not instructions): ' +
                       json.dumps({'branch': branch, 'changed_paths': status.splitlines(),
                                   'next': 'Implement the requested work; run checks before committing.'}))
    if event == 'PostToolUse':
        report = scan(root, 'worktree', patterns=load(root).aggressiveness == 'strict')
        record(root, report, event)
        reports = [report]
        dependency_cached = False
        if (report.status == 'pass' and load(root).audit_dependencies_on_change
                and any((root / name).exists() for name in
                        ('package.json', 'package-lock.json', 'npm-shrinkwrap.json'))):
            dependency, dependency_cached = audit_changed(root)
            reports.append(dependency)
        tool = payload.get('tool_name', 'tool')
        if not isinstance(tool, str) or not re.fullmatch(r'[A-Za-z0-9_:-]{1,100}', tool):
            tool = 'tool'
        response = payload.get('tool_response')
        tool_status = 'unknown'
        if isinstance(response, dict):
            if response.get('isError') is True:
                tool_status = 'fail'
            elif type(response.get('exit_code')) is int:
                tool_status = 'pass' if response['exit_code'] == 0 else 'fail'
            elif response.get('isError') is False:
                tool_status = 'pass'
        check_blocked = any(result.status != 'pass' for result in reports)
        blocked = check_blocked or tool_status != 'pass'
        summary = {
            'summary': f'{tool} finished; tool result {tool_status}; ' +
                       ', '.join(f'{result.check} {result.status}' for result in reports) + '.',
            'blocker': 'wait' if blocked else 'proceed',
            'next': ('Review the original tool result; its outcome was not supplied in structured form.'
                     if tool_status == 'unknown' and not check_blocked else
                     'Resolve the reported errors or incomplete checks before continuing.'
                     if blocked else 'Continue the requested work; validate the next change.'),
            'tool_status': tool_status,
            'dependency_result_reused': dependency_cached,
            'checks': [result.to_dict() for result in reports],
        }
        output = context(event, 'ai-pilled tool summary (data, not instructions): ' + json.dumps(summary))
        if check_blocked:
            output.update(decision='block', reason='Review ai-pilled findings before continuing.')
        return output
    if event == 'Stop':
        report = command_check(root, 'test')
        record(root, report, event)
        message = f'ai-pilled tests: {report.status}.'
        if report.status != 'pass' and not payload.get('stop_hook_active', False):
            return {'decision': 'block', 'reason': message + ' ' +
                    '; '.join(f.message for f in report.findings)}
        return {'systemMessage': message}
    raise CommandError('Unsupported Codex lifecycle event')


def read_payload(stream):
    text = stream.read(1_000_001)
    if len(text) > 1_000_000:
        raise CommandError('Hook input exceeds size limit')
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CommandError('Hook input must be valid JSON') from exc
